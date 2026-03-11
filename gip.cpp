// ─────────────────────────────────────────────────────────────────────────────
// gip.cpp  —  GIP (Get IP Addresses)
//
// Two operating modes:
//   1. Adapter list  (default): enumerate local network adapters and print
//      their IPv4 (and optionally IPv6) addresses to stdout.
//   2. Subnet scan  (-scan <CIDR>): probe every host address in a CIDR range
//      using ARP, then attempt to resolve each responsive host's name via
//      DNS reverse lookup, NetBIOS Node Status, and mDNS PTR query.
//      Results are saved as a self-contained HTML report.
//
// Usage:
//   gip [options]
//
// Options:
//   -6             Show both IPv4 and IPv6 addresses (default: IPv4 only).
//                  Without this flag only AF_INET addresses are retrieved from
//                  GetAdaptersAddresses.
//
//   -L             Include the Loopback adapter in the output.  Loopback is
//                  hidden by default (IF_TYPE_SOFTWARE_LOOPBACK) as it is
//                  rarely useful for network diagnostics.
//
//   -n             Disable colored output.  By default the adapter name is
//                  printed in yellow/cyan using ANSI escape codes.  Use this
//                  flag when piping output to a file or another program.
//
//   -scan <CIDR>   Scan every usable host address in the given subnet and save
//                  an IP / MAC / hostname report as an HTML file.
//                  <CIDR> must be in dotted-decimal/prefix notation, e.g.:
//                    gip -scan 192.168.1.0/24
//                  Prefix must be /1 through /30 (at least two host addresses).
//
//   -o <file>      Specify the output filename for the HTML report produced by
//                  -scan.  If omitted, the file is named automatically:
//                    GIP-Scan_YYYY-MM-DD_HH-MM-SS.html
//
//   -d             Use dark mode for the HTML report (default: light mode).
//
//   -p             Ping 8.8.8.8 and report success or failure with round-trip time.
//
//   -v  -version   Print the version string and exit.
//
//   -help  -?      Print this usage summary and exit.
//
// Windows-specific APIs used:
//   iphlpapi  — SendARP, GetAdaptersAddresses, IcmpSendEcho
//   ws2_32    — Winsock (sockets, getnameinfo, inet_ntop / inet_pton)
// ─────────────────────────────────────────────────────────────────────────────

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>

// Tell the linker to pull in the required Windows libraries automatically
#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "ws2_32")

// ─── Version ──────────────────────────────────────────────────────────────────

#define GIP_VER_MAJOR 1
#define GIP_VER_MINOR 2
#define GIP_VER_PATCH 0
#define GIP_VERSION   "1.2.0"

// ─── Data ─────────────────────────────────────────────────────────────────────

// Holds all scan data collected for a single host address.
// 'ip' is stored in host byte order so arithmetic (sorting, incrementing) is
// straightforward; it is converted to network order only when calling socket APIs.
struct ScanResult {
    DWORD ip;            // host byte order
    BYTE  mac[6];
    bool  alive;
    char  hostname[256];
};

// ─── Name Resolution ──────────────────────────────────────────────────────────
// Each function writes to out[outLen] and returns true on success.
// ipNet is always in network byte order.
//
// Resolution is attempted in priority order:
//   1. dnsReverse  — authoritative / DHCP-registered names (most reliable)
//   2. netbiosName — Windows machine names on older/mixed networks
//   3. mdnsName    — Apple/Linux ".local" names (Bonjour / avahi)

// ---------------------------------------------------------------------------
// dnsReverse — Resolve a hostname via standard reverse DNS (PTR record).
//
// Wraps getnameinfo() which internally performs a PTR lookup for the
// x.x.x.x.in-addr.arpa name.  NI_NAMEREQD makes the call fail (return false)
// if no PTR record exists, rather than falling back to the dotted-decimal IP.
// ---------------------------------------------------------------------------
static bool dnsReverse(DWORD ipNet, char *out, int outLen) {
    sockaddr_in sa = {};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = ipNet;
    return getnameinfo((sockaddr *)&sa, sizeof(sa), out, outLen,
                       nullptr, 0, NI_NAMEREQD) == 0 && out[0];
}

// ---------------------------------------------------------------------------
// netbiosName — Query the host's NetBIOS name via UDP Node Status (port 137).
//
// Sends a raw NetBIOS Node Status Request (NBSTAT query, type 0x21) to the
// target and parses the response to extract the machine's workstation name.
//
// Packet layout (RFC 1002):
//   Bytes  0-1  : Transaction ID  (0xABCD — arbitrary, no matching required)
//   Bytes  2-3  : Flags           (0x0000 = standard query)
//   Bytes  4-5  : QDCOUNT = 1
//   Bytes  6-11 : ANCOUNT / NSCOUNT / ARCOUNT = 0
//   Byte  12    : Question name length = 0x20 (32 encoded bytes follow)
//   Bytes 13-14 : "CK" — first two chars of the half-ASCII-encoded wildcard '*'
//   Bytes 15-44 : 30 × 'A' — remainder of the encoded wildcard name
//   Byte  45    : Root label (0x00)
//   Bytes 46-47 : Type  = 0x0021 (NBSTAT)
//   Bytes 48-49 : Class = 0x0001 (IN)
//
// Response parsing:
//   - Skip the 12-byte DNS header.
//   - Walk the answer name field (handles both full labels and compression
//     pointers so the parser doesn't overrun on either format).
//   - Skip 10 fixed bytes (type, class, TTL, rdlen).
//   - Read the name table: each entry is 18 bytes — 15-byte padded name,
//     1-byte type, 2-byte flags.
//   - Select the first entry with type 0x00 (Workstation) that is NOT a group
//     name (group bit 0x8000 in flags is clear) — that is the machine name.
// ---------------------------------------------------------------------------
static bool netbiosName(DWORD ipNet, char *out, int outLen) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;

    // 1.5-second receive timeout — NetBIOS hosts should reply almost instantly
    // on a LAN; anything slower is likely a firewall drop.
    DWORD tv = 1500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

    // NetBIOS Node Status request — wildcard '*', NBSTAT query
    static const unsigned char pkt[50] = {
        0xAB,0xCD, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x20,
        'C','K',
        'A','A','A','A','A','A','A','A','A','A',
        'A','A','A','A','A','A','A','A','A','A',
        'A','A','A','A','A','A','A','A','A','A',
        0x00, 0x00,0x21, 0x00,0x01
    };

    sockaddr_in dest = {};
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(137);   // NetBIOS Name Service port
    dest.sin_addr.s_addr = ipNet;

    if (sendto(s, (char *)pkt, sizeof(pkt), 0,
               (sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
        closesocket(s); return false;
    }

    unsigned char resp[1024];
    int rlen = recv(s, (char *)resp, sizeof(resp), 0);
    closesocket(s);
    // Minimum valid response is 57 bytes (12 header + at least one 18-byte entry
    // plus the name/type/class/TTL/rdlen overhead before the name table).
    if (rlen < 57) return false;

    // Skip answer name — may be full label sequence or a compression pointer.
    // A compression pointer starts with bits 11xxxxxx (0xC0 mask).
    int npos = 12;
    while (npos < rlen) {
        int lab = (unsigned char)resp[npos++];
        if (!lab) break;                        // root label = end of name
        if ((lab & 0xC0) == 0xC0) { npos++; break; }  // compression pointer (2 bytes total)
        npos += lab;                            // skip label data bytes
    }
    npos += 10; // type(2) + class(2) + TTL(4) + rdlen(2)
    if (npos >= rlen) return false;

    // The first byte of the RDATA is the number of name entries (NRNAMES)
    int nrnames = (unsigned char)resp[npos++];
    if (!nrnames || rlen < npos + nrnames * 18) return false;

    for (int i = 0; i < nrnames; i++) {
        unsigned char *e     = resp + npos + i * 18;
        unsigned short flags = (unsigned short)((e[16] << 8) | e[17]);
        // Type 0x00 = Workstation, unique (not group) = machine name
        if (e[15] == 0x00 && !(flags & 0x8000)) {
            // Name is padded to 15 bytes with spaces; strip trailing spaces
            char name[16] = {};
            memcpy(name, e, 15);
            for (int j = 14; j >= 0 && name[j] == ' '; j--) name[j] = '\0';
            if (name[0]) {
                strncpy(out, name, outLen - 1);
                out[outLen - 1] = '\0';
                return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// mdnsName — Resolve a hostname via multicast DNS (mDNS, RFC 6762).
//
// Sends a unicast mDNS PTR query directly to the target host on UDP port 5353.
// Although mDNS is normally multicast, sending it unicast with the QU bit set
// (class field 0x8001) is valid and avoids flooding the multicast group.
//
// The query asks for the PTR record of d.c.b.a.in-addr.arpa (reversed octets),
// which Apple/avahi responders answer with the ".local" hostname.
//
// Packet construction:
//   - 12-byte DNS header: TxID=1, standard query, QDCOUNT=1
//   - Question QNAME: each label encoded as (length byte)(data), terminated 0x00
//   - QTYPE  = 0x000C (PTR)
//   - QCLASS = 0x8001 (IN + QU bit — request unicast response)
//
// Response parsing:
//   - Validate ANCOUNT > 0 in the header.
//   - Walk past the question section (mirrored back in the response).
//   - In the answer section, find a record with type 12 (PTR).
//   - Decode the PTR RDATA as a DNS name (handles compression pointers).
//   - Strip the ".local" suffix, leaving just the hostname.
// ---------------------------------------------------------------------------
static bool mdnsName(DWORD ipNet, char *out, int outLen) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;

    // 1.5-second timeout — mDNS on a local network should be near-instant
    DWORD tv = 1500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

    // Build the reversed dotted-decimal in-addr.arpa name for the PTR query.
    // e.g. 192.168.1.5 → "5.1.168.192.in-addr.arpa"
    // PTR query for d.c.b.a.in-addr.arpa (reversed octets)
    const unsigned char *b = (const unsigned char *)&ipNet;
    char qname[64];
    snprintf(qname, sizeof(qname), "%d.%d.%d.%d.in-addr.arpa",
             b[3], b[2], b[1], b[0]);

    unsigned char pkt[512];
    int pos = 0;
    // DNS header
    pkt[pos++]=0x00; pkt[pos++]=0x01;  // Transaction ID
    pkt[pos++]=0x00; pkt[pos++]=0x00;  // Flags: standard query
    pkt[pos++]=0x00; pkt[pos++]=0x01;  // QDCOUNT: 1
    pkt[pos++]=0x00; pkt[pos++]=0x00;  // ANCOUNT: 0
    pkt[pos++]=0x00; pkt[pos++]=0x00;  // NSCOUNT: 0
    pkt[pos++]=0x00; pkt[pos++]=0x00;  // ARCOUNT: 0

    // Encode domain labels: split on '.' and prefix each segment with its length.
    // e.g. "5.1.168.192.in-addr.arpa" → \x01 '5' \x01 '1' ...
    for (const char *p = qname; *p; ) {
        const char *dot = strchr(p, '.');
        int lablen = dot ? (int)(dot - p) : (int)strlen(p);
        pkt[pos++] = (unsigned char)lablen;
        memcpy(pkt + pos, p, lablen);
        pos += lablen;
        p   += lablen;
        if (*p == '.') p++;
    }
    pkt[pos++]=0x00;            // root label — terminates the QNAME
    pkt[pos++]=0x00; pkt[pos++]=0x0C;  // Type: PTR (12)
    pkt[pos++]=0x80; pkt[pos++]=0x01;  // Class: IN + QU bit (unicast response)

    sockaddr_in dest = {};
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(5353); // mDNS port
    dest.sin_addr.s_addr = ipNet;

    if (sendto(s, (char *)pkt, pos, 0,
               (sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
        closesocket(s); return false;
    }

    unsigned char resp[512];
    int rlen = recv(s, (char *)resp, sizeof(resp), 0);
    closesocket(s);
    if (rlen < 12) return false;  // must have at least a DNS header

    // Check that the response contains at least one answer
    int ancount = (resp[6] << 8) | resp[7];
    if (!ancount) return false;

    // Skip question section — the response echoes back all questions first.
    // Walk each question's QNAME label sequence, then skip 4 bytes (type + class).
    int rpos = 12;
    for (int q = 0, qd = (resp[4]<<8)|resp[5]; q < qd && rpos < rlen; q++) {
        while (rpos < rlen) {
            int lab = (unsigned char)resp[rpos++];
            if (!lab) break;
            if ((lab & 0xC0) == 0xC0) { rpos++; break; }  // compression pointer
            rpos += lab;
        }
        rpos += 4; // type + class
    }

    // Scan answer records for PTR (type 12)
    for (int i = 0; i < ancount && rpos < rlen; i++) {
        // Walk the answer record's NAME field (may also use a compression pointer)
        while (rpos < rlen) {
            int lab = (unsigned char)resp[rpos++];
            if (!lab) break;
            if ((lab & 0xC0) == 0xC0) { rpos++; break; }
            rpos += lab;
        }
        if (rpos + 10 > rlen) break;
        // Read TYPE (2 bytes), skip CLASS (2), TTL (4), then read RDLENGTH (2)
        int type  = (resp[rpos] << 8) | resp[rpos+1]; rpos += 8;
        int rdlen = (resp[rpos] << 8) | resp[rpos+1]; rpos += 2;

        if (type == 12) {  // PTR record — RDATA is the target hostname as a DNS name
            char name[256] = {};
            int  nptr = rpos, nlen = 0, safety = 20;  // safety limits pointer-following loops
            bool first = true;
            while (nptr < rlen && nlen < 254 && safety-- > 0) {
                int lab = (unsigned char)resp[nptr++];
                if (!lab) break;
                if ((lab & 0xC0) == 0xC0) {
                    // Compression pointer: upper 6 bits of this byte + next byte = offset
                    if (nptr >= rlen) break;
                    nptr = ((lab & 0x3F) << 8) | (unsigned char)resp[nptr];
                    continue;
                }
                if (!first) name[nlen++] = '.';  // separate labels with dots
                if (nptr + lab > rlen) break;
                memcpy(name + nlen, resp + nptr, lab);
                nlen += lab; nptr += lab; first = false;
            }
            name[nlen] = '\0';

            // Strip ".local" suffix — mDNS names end with ".local" by convention
            char *dot = strstr(name, ".local");
            if (dot) *dot = '\0';
            if (name[0]) {
                strncpy(out, name, outLen - 1);
                out[outLen - 1] = '\0';
                return true;
            }
        }
        rpos += rdlen;  // advance past this record's RDATA to the next record
    }
    return false;
}

// ─── Host Thread: ARP then resolve (single pass per host) ────────────────────

// Arguments passed to each per-host worker thread.
// ipNet is in network byte order (as required by SendARP and socket APIs).
struct HostArg {
    DWORD       ipNet;   // network byte order
    ScanResult *result;
};

// ---------------------------------------------------------------------------
// hostThread — Worker thread that probes one host and resolves its name.
//
// Step 1: Send an ARP request via SendARP().  If the host doesn't respond,
//         the thread exits immediately (host is unreachable or offline).
//         On success the MAC address is written into result->mac.
//
// Step 2: Attempt hostname resolution using three methods in priority order:
//           a) DNS reverse lookup  (dnsReverse)
//           b) NetBIOS Node Status (netbiosName)
//           c) mDNS PTR query      (mdnsName)
//         The first method that returns a non-empty name wins; subsequent
//         methods are skipped via short-circuit evaluation.
//
// This function is launched as a Windows thread (CreateThread) for every host
// in the subnet so that all ARP probes run concurrently.
// ---------------------------------------------------------------------------
static DWORD WINAPI hostThread(LPVOID param) {
    HostArg    *a   = (HostArg *)param;
    ScanResult *res = a->result;
    ULONG macLen = 6;

    // SendARP triggers an ARP request and blocks until a reply arrives or the
    // system-level timeout expires (~2 seconds on Windows).  Returns NO_ERROR
    // only if the host responded with its MAC address.
    if (SendARP(a->ipNet, 0, res->mac, &macLen) != NO_ERROR) return 0;

    res->alive = true;
    char *h = res->hostname;
    // Try each method in order; stop at first success
    if (!dnsReverse(a->ipNet, h, 256) &&
        !netbiosName(a->ipNet, h, 256))
         mdnsName(a->ipNet, h, 256);
    return 0;
}

// ─── Subnet Scan ─────────────────────────────────────────────────────────────

// ---------------------------------------------------------------------------
// parseCIDR — Parse a CIDR string (e.g. "192.168.1.0/24") into components.
//
// Returns false if the string is malformed, the prefix is out of range
// (we only support /1–/30; /31 and /32 have no usable host addresses), or
// the IP portion is not a valid IPv4 address.
//
// On success, *netHost receives the network address in HOST byte order, and
// *prefix receives the prefix length as an integer.
// ---------------------------------------------------------------------------
static bool parseCIDR(const char *cidr, DWORD *netHost, int *prefix) {
    char buf[40];
    strncpy(buf, cidr, 39); buf[39] = '\0';
    char *slash = strchr(buf, '/');
    if (!slash) return false;
    *slash = '\0';                      // split "a.b.c.d" and "prefix"
    *prefix = atoi(slash + 1);
    if (*prefix < 1 || *prefix > 30) return false;
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return false;
    *netHost = ntohl(a.s_addr);         // convert to host order for arithmetic
    return true;
}

// ---------------------------------------------------------------------------
// runScan — Orchestrate a full subnet scan and write an HTML report.
//
// Algorithm:
//   1. Parse the CIDR notation to get the first and last usable host addresses.
//   2. Allocate a ScanResult for every address in the range.
//   3. Process hosts in batches of up to 256 at a time:
//        - Spawn one thread per host (hostThread) — all ARP probes run in
//          parallel, dramatically reducing total scan time.
//        - Wait for each batch with WaitForMultipleObjects.  Because
//          WaitForMultipleObjects accepts at most MAXIMUM_WAIT_OBJECTS (64)
//          handles at once, large batches are waited in 64-handle sub-groups.
//        - Batch timeout of 15 seconds covers ARP (~2 s), plus DNS/NetBIOS/mDNS
//          resolution (~5 s each sequentially) with comfortable margin.
//   4. Write results to a self-contained HTML file showing only alive hosts.
//
// The generated filename defaults to "GIP-Scan_YYYY-MM-DD_HH-MM-SS.html"
// if no -o argument was provided.
// ---------------------------------------------------------------------------
static int runScan(const char *subnet, const char *outFile, bool darkMode) {
    // Build default filename GIP-Scan_YYYY-MM-DD_HH-MM-SS.html if none given
    char generatedName[64];
    if (!outFile) {
        time_t now = time(nullptr);
        strftime(generatedName, sizeof(generatedName),
                 "GIP-Scan_%Y-%m-%d_%H-%M-%S.html", localtime(&now));
        outFile = generatedName;
    }

    DWORD netHost; int prefix;
    if (!parseCIDR(subnet, &netHost, &prefix)) {
        fprintf(stderr,
            "Invalid subnet '%s'. Use CIDR notation, e.g. 192.168.1.0/24\n"
            "(Prefix must be /1 through /30)\n", subnet);
        return 1;
    }

    // Compute the usable host address range.
    // mask   = all-ones shifted left by (32 - prefix) — e.g. /24 → 0xFFFFFF00
    // first  = network address + 1 (skip network address)
    // last   = broadcast address - 1 (skip broadcast)
    DWORD mask  = (~0u << (32 - prefix));
    DWORD first = (netHost & mask) + 1;
    DWORD last  = (netHost | ~mask) - 1;
    if (first > last) { fprintf(stderr, "Subnet too small to scan.\n"); return 1; }

    DWORD total = last - first + 1;
    printf("Scanning %s (%lu hosts)...\n", subnet, (unsigned long)total);

    // Pre-allocate all result slots and zero them out
    std::vector<ScanResult> results(total);
    for (auto &r : results) { r.alive = false; memset(r.mac, 0, 6); r.hostname[0] = '\0'; }

    // Each thread does ARP + name resolution.
    // 15s batch timeout: covers ARP (~2s) + DNS + NetBIOS + mDNS (~5s) + margin.
    const DWORD BATCH    = 256;
    const DWORD TIMEOUT  = 15000;

    // Process hosts in batches to limit the number of simultaneous threads.
    // For a /24 (254 hosts) this is a single batch; larger subnets get multiple.
    for (DWORD base = 0; base < total; base += BATCH) {
        DWORD bsz = (base + BATCH <= total) ? BATCH : total - base;

        std::vector<HANDLE>  handles(bsz);
        std::vector<HostArg> args(bsz);

        // Spawn one thread per host in this batch
        for (DWORD j = 0; j < bsz; j++) {
            DWORD i        = base + j;
            results[i].ip  = first + i;          // store in host byte order
            args[j].ipNet  = htonl(first + i);   // thread needs network byte order
            args[j].result = &results[i];
            handles[j]     = CreateThread(nullptr, 0, hostThread, &args[j], 0, nullptr);
        }

        // WaitForMultipleObjects is limited to MAXIMUM_WAIT_OBJECTS (64) handles
        // per call.  Loop in sub-groups to wait for all threads in the batch.
        for (DWORD j = 0; j < bsz; j += MAXIMUM_WAIT_OBJECTS) {
            DWORD end = (j + MAXIMUM_WAIT_OBJECTS < bsz) ? j + MAXIMUM_WAIT_OBJECTS : bsz;
            WaitForMultipleObjects(end - j, &handles[j], TRUE, TIMEOUT);
        }

        // Close all thread handles now that they have completed (or timed out)
        for (DWORD j = 0; j < bsz; j++) CloseHandle(handles[j]);

        // \r keeps the progress on a single line in the console
        printf("  Progress: %lu / %lu\r",
               (unsigned long)(base + bsz), (unsigned long)total);
        fflush(stdout);
    }
    printf("  Progress: %lu / %lu\n", (unsigned long)total, (unsigned long)total);

    // ── Write HTML report ──
    // The report is a single self-contained HTML file with embedded CSS.
    // Only alive hosts are included in the table; the header stats show totals.
    FILE *f = fopen(outFile, "w");
    if (!f) { fprintf(stderr, "Cannot write: %s\n", outFile); return 1; }

    // Timestamp for the report header
    time_t now = time(nullptr);
    char ts[64];
    strftime(ts, sizeof(ts), "%B %d, %Y &mdash; %H:%M:%S", localtime(&now));

    // Count alive hosts for the statistics cards
    int alive = 0;
    for (const auto &r : results) if (r.alive) alive++;

    // Emit the HTML document: header, embedded CSS, stat cards, table header.
    // %% escapes literal '%' inside a printf format string.

    // Light mode CSS
    const char *lightCSS =
"*{box-sizing:border-box;margin:0;padding:0}\n"
"body{font-family:'Segoe UI',Arial,sans-serif;background:#f8f9fa;color:#212529;min-height:100vh}\n"
"header{background:linear-gradient(135deg,#ffffff 0%%,#f0f1f3 100%%);padding:2rem 2.5rem;border-bottom:2px solid #0d6efd}\n"
"h1{font-size:1.6rem;color:#0d6efd;letter-spacing:1px}\n"
"h1 .sub{color:#198754;font-size:.85rem;font-weight:normal;margin-left:1rem;letter-spacing:0}\n"
".meta{color:#6c757d;margin-top:.5rem;font-size:.85rem}\n"
".stats{display:flex;gap:1rem;padding:1.2rem 2.5rem;background:#ffffff;border-bottom:1px solid #dee2e6;flex-wrap:wrap}\n"
".card{background:#f8f9fa;border:1px solid #dee2e6;border-radius:6px;padding:.8rem 1.4rem;text-align:center;min-width:110px}\n"
".card .v{font-size:2rem;font-weight:700;color:#0d6efd}\n"
".card .l{font-size:.7rem;color:#6c757d;text-transform:uppercase;letter-spacing:1px;margin-top:.2rem}\n"
".card.ok .v{color:#198754}\n"
".card.no .v{color:#adb5bd}\n"
".wrap{padding:1.5rem 2.5rem 3rem}\n"
"table{width:100%%;border-collapse:collapse;font-size:.9rem;border:1px solid #dee2e6;border-radius:6px;overflow:hidden}\n"
"thead th{background:#e9ecef;padding:.8rem 1.2rem;text-align:left;font-size:.7rem;text-transform:uppercase;"
"letter-spacing:1.5px;color:#495057;border-bottom:2px solid #0d6efd;white-space:nowrap}\n"
"tbody tr{border-bottom:1px solid #dee2e6;transition:background .1s}\n"
"tbody tr:hover{background:#f0f1f3}\n"
"tbody tr:last-child{border-bottom:none}\n"
"td{padding:.7rem 1.2rem;font-family:'Cascadia Code','Consolas','Courier New',monospace;font-size:.88rem}\n"
".n{color:#adb5bd;width:50px}\n"
".ip{color:#0d6efd}\n"
".mac{color:#198754}\n"
".host{color:#b45309}\n"
".none{color:#adb5bd;font-style:italic}\n"
"footer{text-align:center;padding:1.2rem;color:#adb5bd;font-size:.75rem;border-top:1px solid #dee2e6}\n";

    // Dark mode CSS
    const char *darkCSS =
"*{box-sizing:border-box;margin:0;padding:0}\n"
"body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}\n"
"header{background:linear-gradient(135deg,#161b22 0%%,#0d1117 100%%);padding:2rem 2.5rem;border-bottom:2px solid #238636}\n"
"h1{font-size:1.6rem;color:#58a6ff;letter-spacing:1px}\n"
"h1 .sub{color:#3fb950;font-size:.85rem;font-weight:normal;margin-left:1rem;letter-spacing:0}\n"
".meta{color:#8b949e;margin-top:.5rem;font-size:.85rem}\n"
".stats{display:flex;gap:1rem;padding:1.2rem 2.5rem;background:#161b22;border-bottom:1px solid #30363d;flex-wrap:wrap}\n"
".card{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:.8rem 1.4rem;text-align:center;min-width:110px}\n"
".card .v{font-size:2rem;font-weight:700;color:#58a6ff}\n"
".card .l{font-size:.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-top:.2rem}\n"
".card.ok .v{color:#3fb950}\n"
".card.no .v{color:#6e7681}\n"
".wrap{padding:1.5rem 2.5rem 3rem}\n"
"table{width:100%%;border-collapse:collapse;font-size:.9rem;border:1px solid #21262d;border-radius:6px;overflow:hidden}\n"
"thead th{background:#161b22;padding:.8rem 1.2rem;text-align:left;font-size:.7rem;text-transform:uppercase;"
"letter-spacing:1.5px;color:#8b949e;border-bottom:2px solid #238636;white-space:nowrap}\n"
"tbody tr{border-bottom:1px solid #21262d;transition:background .1s}\n"
"tbody tr:hover{background:#161b22}\n"
"tbody tr:last-child{border-bottom:none}\n"
"td{padding:.7rem 1.2rem;font-family:'Cascadia Code','Consolas','Courier New',monospace;font-size:.88rem}\n"
".n{color:#484f58;width:50px}\n"
".ip{color:#58a6ff}\n"
".mac{color:#3fb950}\n"
".host{color:#e3b341}\n"
".none{color:#484f58;font-style:italic}\n"
"footer{text-align:center;padding:1.2rem;color:#484f58;font-size:.75rem;border-top:1px solid #21262d}\n";

    const char *css = darkMode ? darkCSS : lightCSS;

    fprintf(f,
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"<meta charset=\"UTF-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<title>Subnet Scan &mdash; %s</title>\n"
"<style>\n"
"%s"
"</style>\n"
"</head>\n"
"<body>\n"
"<header>\n"
"  <h1>GIP &mdash; Subnet Scan <span class=\"sub\">%s</span></h1>\n"
"  <div class=\"meta\">Scanned: %s</div>\n"
"</header>\n"
"<div class=\"stats\">\n"
"  <div class=\"card\"><div class=\"v\">%lu</div><div class=\"l\">Hosts Scanned</div></div>\n"
"  <div class=\"card ok\"><div class=\"v\">%d</div><div class=\"l\">Active</div></div>\n"
"  <div class=\"card no\"><div class=\"v\">%d</div><div class=\"l\">No Response</div></div>\n"
"</div>\n"
"<div class=\"wrap\">\n"
"<table>\n"
"<thead><tr><th>#</th><th>IP Address</th><th>MAC Address</th><th>Hostname</th></tr></thead>\n"
"<tbody>\n",
        subnet, css, subnet, ts, (unsigned long)total, alive, (int)total - alive);

    // Emit one table row per alive host.
    // Hosts without a resolved name display an em-dash styled with the "none" CSS class.
    int n = 1;
    for (const auto &r : results) {
        if (!r.alive) continue;

        // Convert host-order IP back to network order for inet_ntop
        struct in_addr a; a.s_addr = htonl(r.ip);
        char ipbuf[INET_ADDRSTRLEN], macbuf[18];
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
        // Format MAC as XX:XX:XX:XX:XX:XX (uppercase hex)
        snprintf(macbuf, sizeof(macbuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 r.mac[0], r.mac[1], r.mac[2], r.mac[3], r.mac[4], r.mac[5]);
        fprintf(f,
            "<tr><td class=\"n\">%d</td>"
            "<td class=\"ip\">%s</td>"
            "<td class=\"mac\">%s</td>"
            "<td class=\"%s\">%s</td></tr>\n",
            n++, ipbuf, macbuf,
            r.hostname[0] ? "host" : "none",
            r.hostname[0] ? r.hostname : "&mdash;");
    }

    fputs(
"</tbody>\n</table>\n</div>\n"
"<footer>Generated by GIP " GIP_VERSION " &mdash; Get IP Addresses</footer>\n"
"</body>\n</html>\n", f);

    fclose(f);
    printf("Report saved: %s\n", outFile);
    return 0;
}

// ─── Ping Check ───────────────────────────────────────────────────────────────

// ---------------------------------------------------------------------------
// pingCheck — Send a single ICMP echo request to 8.8.8.8 via IcmpSendEcho.
//
// Returns the round-trip time in milliseconds on success, or -1 on failure.
// Uses the Windows ICMP API (IcmpCreateFile / IcmpSendEcho / IcmpCloseHandle)
// which does not require elevated privileges or raw socket access.
// ---------------------------------------------------------------------------
static int pingCheck() {
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return -1;

    DWORD dest;
    inet_pton(AF_INET, "8.8.8.8", &dest);

    char sendData[32] = "gip";
    BYTE replyBuf[sizeof(ICMP_ECHO_REPLY) + sizeof(sendData)];

    DWORD ret = IcmpSendEcho(hIcmp, dest, sendData, (WORD)sizeof(sendData),
                             nullptr, replyBuf, sizeof(replyBuf), 3000);
    IcmpCloseHandle(hIcmp);

    if (ret > 0) {
        PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)replyBuf;
        if (reply->Status == IP_SUCCESS)
            return (int)reply->RoundTripTime;
    }
    return -1;
}

// ─── Adapter List (original functionality) ───────────────────────────────────

// Print the program version string to stdout
static void printVersion() {
    fputs("gip " GIP_VERSION " (built " __DATE__ ")\n", stdout);
}

// Print version plus full usage information to stdout
static void printHelp() {
    printVersion();
    fputs(
        "\nUsage: gip [options]\n"
        "\n"
        "Options:\n"
        "  -6             Show both IPv4 and IPv6 addresses (default: IPv4 only)\n"
        "  -L             Include the Loopback adapter (hidden by default)\n"
        "  -n             Disable colored output\n"
        "  -d             Use dark mode for the HTML scan report (default: light)\n"
        "  -scan <CIDR>   Scan a subnet and save IP/MAC/hostname report as HTML\n"
        "                 Example: gip -scan 192.168.1.0/24\n"
        "  -o <file>      Output HTML filename for -scan\n"
        "                 (default: GIP-Scan_YYYY-MM-DD_HH-MM-SS.html)\n"
        "  -p             Ping 8.8.8.8 and report success or failure\n"
        "  -v             Show version\n"
        "  -help          Show this help message\n"
        "  -?             Show this help message\n", stdout);
}

// ---------------------------------------------------------------------------
// main — Entry point: parse arguments, initialise Winsock, dispatch mode.
//
// Adapter list mode (default):
//   1. Enable ANSI escape sequences on the console (ENABLE_VIRTUAL_TERMINAL_PROCESSING)
//      so colored output works on Windows 10+.  Falls back gracefully if the
//      handle is not a real console (e.g. redirected to a file).
//   2. Call GetAdaptersAddresses() with a retry loop: the required buffer size
//      is not known in advance so we start with 15 KB and grow on
//      ERROR_BUFFER_OVERFLOW (up to 3 attempts).
//   3. Walk the linked list of IP_ADAPTER_ADDRESSES structures, skipping
//      adapters that are down or (unless -L) are loopback.
//   4. For each relevant adapter, walk its unicast address list and print
//      each IPv4 (and optionally IPv6) address.  The adapter's friendly name
//      is printed once before its first address using WideCharToMultiByte
//      to convert the wide-character name to UTF-8.
//
// Subnet scan mode (-scan):
//   Delegates entirely to runScan() and then exits.
// ---------------------------------------------------------------------------
int main(int argc, char *argv[]) {
    bool        showIPv6   = false;
    bool        showLoop   = false;
    bool        useColor   = true;
    bool        doScan     = false;
    bool        darkMode   = false;
    bool        doPing     = false;
    const char *scanSubnet = nullptr;
    const char *outFile    = nullptr;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "-6")    == 0) showIPv6 = true;
        else if (strcmp(argv[i], "-d")    == 0) darkMode = true;
        else if (strcmp(argv[i], "-n")    == 0) useColor = false;
        else if (strcmp(argv[i], "-L")    == 0) showLoop = true;
        else if (strcmp(argv[i], "-p")    == 0) doPing   = true;
        else if (strcmp(argv[i], "-scan") == 0) {
            if (i + 1 >= argc) {
                fputs("-scan requires a CIDR argument (e.g. 192.168.1.0/24)\n", stderr);
                return 1;
            }
            scanSubnet = argv[++i]; doScan = true;
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) { fputs("-o requires a filename\n", stderr); return 1; }
            outFile = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "-version") == 0) {
            printVersion(); return 0;
        } else if (strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "-?") == 0) {
            printHelp(); return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            printHelp(); return 1;
        }
    }

    // Winsock required for getnameinfo, socket, inet_ntop, inet_pton
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fputs("WSAStartup failed\n", stderr); return 1;
    }

    int exitCode = 0;

    // If -p was requested, ping 8.8.8.8 and exit
    if (doPing) {
        int rtt = pingCheck();
        if (rtt >= 0)
            printf("Ping 8.8.8.8: OK (%d ms)\n", rtt);
        else
            fputs("Ping 8.8.8.8: FAILED\n", stdout);
        WSACleanup();
        return (rtt >= 0) ? 0 : 1;
    }

    // If -scan was requested, delegate to runScan and exit immediately
    if (doScan) {
        exitCode = runScan(scanSubnet, outFile, darkMode);
        WSACleanup();
        return exitCode;
    }

    // ── List local adapters ──

    // Attempt to enable ANSI/VT100 color escape sequences.
    // GetConsoleMode fails when stdout is redirected (e.g. piped to a file),
    // in which case we disable color automatically.
    if (useColor) {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(hOut, &mode))
                useColor = SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
            else
                useColor = false;  // not a console (redirected) — suppress escape codes
        } else {
            useColor = false;
        }
    }

    // Set up ANSI escape code strings — empty strings if color is disabled
    const char *yellow = useColor ? "\033[33m" : "";
    const char *cyan   = useColor ? "\033[36m" : "";
    const char *reset  = useColor ? "\033[0m"  : "";

    // AF_UNSPEC retrieves both IPv4 and IPv6; AF_INET retrieves only IPv4
    ULONG family = showIPv6 ? AF_UNSPEC : AF_INET;
    ULONG bufLen = 15000;   // initial buffer estimate; grown on overflow
    PIP_ADAPTER_ADDRESSES addrs = nullptr;
    DWORD result;
    int   retries = 0;

    // GetAdaptersAddresses requires a caller-allocated buffer whose required
    // size is returned in bufLen on ERROR_BUFFER_OVERFLOW.  Retry up to 3
    // times in case another adapter is added between calls.
    do {
        addrs = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
        if (!addrs) { fputs("Memory allocation failed\n", stderr); exitCode = 1; goto done; }
        result = GetAdaptersAddresses(family, GAA_FLAG_INCLUDE_PREFIX, nullptr, addrs, &bufLen);
        if (result == ERROR_BUFFER_OVERFLOW) { free(addrs); addrs = nullptr; retries++; }
    } while (result == ERROR_BUFFER_OVERFLOW && retries < 3);

    if (result != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses failed: %lu\n", result);
        exitCode = 1; goto done;
    }

    {
        // Output is accumulated in a stack buffer to reduce the number of
        // write() system calls.  Flushed automatically when the buffer nears full.
        char ip[INET6_ADDRSTRLEN], adapterName[256], buf[4096];
        int  len = snprintf(buf, sizeof(buf), "\n");

        // Walk the singly-linked list of adapter structures
        for (PIP_ADAPTER_ADDRESSES ad = addrs; ad; ad = ad->Next) {
            if (ad->OperStatus != IfOperStatusUp) continue;              // skip down adapters
            if (!showLoop && ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue; // skip loopback unless -L

            bool printed = false;  // tracks whether the adapter header line has been emitted

            // Walk the unicast address list for this adapter
            for (PIP_ADAPTER_UNICAST_ADDRESS ua = ad->FirstUnicastAddress; ua; ua = ua->Next) {
                SOCKADDR *sa = ua->Address.lpSockaddr;
                if (!sa) continue;

                // Select the label and address pointer based on address family
                const char *label; void *addrPtr;
                if      (sa->sa_family == AF_INET)
                    { label = "  IPv4: "; addrPtr = &((sockaddr_in  *)sa)->sin_addr; }
                else if (sa->sa_family == AF_INET6)
                    { label = "  IPv6: "; addrPtr = &((sockaddr_in6 *)sa)->sin6_addr; }
                else continue;  // skip other address families (e.g. AF_LINK)

                inet_ntop(sa->sa_family, addrPtr, ip, sizeof(ip));

                // Print the adapter name once — before the first address
                if (!printed) {
                    // FriendlyName is a wide (UTF-16) string; convert to UTF-8 for printf
                    WideCharToMultiByte(CP_UTF8, 0, ad->FriendlyName, -1,
                                        adapterName, sizeof(adapterName), nullptr, nullptr);
                    len += snprintf(buf + len, sizeof(buf) - len,
                                    "%sAdapter: %s%s%s%s\n",
                                    yellow, reset, cyan, adapterName, reset);
                    printed = true;
                }
                len += snprintf(buf + len, sizeof(buf) - len, "%s%s\n", label, ip);

                // Flush accumulated output if the buffer is nearly full
                if ((size_t)len >= sizeof(buf) - 256) { fwrite(buf, 1, len, stdout); len = 0; }
            }
            if (printed) len += snprintf(buf + len, sizeof(buf) - len, "\n");
        }
        if (len > 0) fwrite(buf, 1, len, stdout);  // flush any remaining buffered output
    }

done:
    free(addrs);
    WSACleanup();
    return exitCode;
}
