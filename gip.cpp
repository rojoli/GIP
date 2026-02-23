#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>

#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "ws2_32")

// ─── Version ──────────────────────────────────────────────────────────────────

#define GIP_VER_MAJOR 1
#define GIP_VER_MINOR 1
#define GIP_VER_PATCH 0
#define GIP_VERSION   "1.1.0"

// ─── Data ─────────────────────────────────────────────────────────────────────

struct ScanResult {
    DWORD ip;            // host byte order
    BYTE  mac[6];
    bool  alive;
    char  hostname[256];
};

// ─── Name Resolution ──────────────────────────────────────────────────────────
// Each function writes to out[outLen] and returns true on success.
// ipNet is always in network byte order.

static bool dnsReverse(DWORD ipNet, char *out, int outLen) {
    sockaddr_in sa = {};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = ipNet;
    return getnameinfo((sockaddr *)&sa, sizeof(sa), out, outLen,
                       nullptr, 0, NI_NAMEREQD) == 0 && out[0];
}

static bool netbiosName(DWORD ipNet, char *out, int outLen) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;

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
    dest.sin_port        = htons(137);
    dest.sin_addr.s_addr = ipNet;

    if (sendto(s, (char *)pkt, sizeof(pkt), 0,
               (sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
        closesocket(s); return false;
    }

    unsigned char resp[1024];
    int rlen = recv(s, (char *)resp, sizeof(resp), 0);
    closesocket(s);
    if (rlen < 57) return false;

    // Skip answer name (full labels or compression pointer)
    int npos = 12;
    while (npos < rlen) {
        int lab = (unsigned char)resp[npos++];
        if (!lab) break;
        if ((lab & 0xC0) == 0xC0) { npos++; break; }
        npos += lab;
    }
    npos += 10; // type(2) + class(2) + TTL(4) + rdlen(2)
    if (npos >= rlen) return false;

    int nrnames = (unsigned char)resp[npos++];
    if (!nrnames || rlen < npos + nrnames * 18) return false;

    for (int i = 0; i < nrnames; i++) {
        unsigned char *e     = resp + npos + i * 18;
        unsigned short flags = (unsigned short)((e[16] << 8) | e[17]);
        // Type 0x00 = Workstation, unique (not group) = machine name
        if (e[15] == 0x00 && !(flags & 0x8000)) {
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

static bool mdnsName(DWORD ipNet, char *out, int outLen) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;

    DWORD tv = 1500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

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
    // Encode domain labels
    for (const char *p = qname; *p; ) {
        const char *dot = strchr(p, '.');
        int lablen = dot ? (int)(dot - p) : (int)strlen(p);
        pkt[pos++] = (unsigned char)lablen;
        memcpy(pkt + pos, p, lablen);
        pos += lablen;
        p   += lablen;
        if (*p == '.') p++;
    }
    pkt[pos++]=0x00;            // root label
    pkt[pos++]=0x00; pkt[pos++]=0x0C;  // Type: PTR
    pkt[pos++]=0x80; pkt[pos++]=0x01;  // Class: IN + QU bit (unicast response)

    sockaddr_in dest = {};
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(5353);
    dest.sin_addr.s_addr = ipNet;

    if (sendto(s, (char *)pkt, pos, 0,
               (sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
        closesocket(s); return false;
    }

    unsigned char resp[512];
    int rlen = recv(s, (char *)resp, sizeof(resp), 0);
    closesocket(s);
    if (rlen < 12) return false;

    int ancount = (resp[6] << 8) | resp[7];
    if (!ancount) return false;

    // Skip question section
    int rpos = 12;
    for (int q = 0, qd = (resp[4]<<8)|resp[5]; q < qd && rpos < rlen; q++) {
        while (rpos < rlen) {
            int lab = (unsigned char)resp[rpos++];
            if (!lab) break;
            if ((lab & 0xC0) == 0xC0) { rpos++; break; }
            rpos += lab;
        }
        rpos += 4; // type + class
    }

    // Scan answer records for PTR (type 12)
    for (int i = 0; i < ancount && rpos < rlen; i++) {
        while (rpos < rlen) {
            int lab = (unsigned char)resp[rpos++];
            if (!lab) break;
            if ((lab & 0xC0) == 0xC0) { rpos++; break; }
            rpos += lab;
        }
        if (rpos + 10 > rlen) break;
        int type  = (resp[rpos] << 8) | resp[rpos+1]; rpos += 8;
        int rdlen = (resp[rpos] << 8) | resp[rpos+1]; rpos += 2;

        if (type == 12) {  // PTR
            char name[256] = {};
            int  nptr = rpos, nlen = 0, safety = 20;
            bool first = true;
            while (nptr < rlen && nlen < 254 && safety-- > 0) {
                int lab = (unsigned char)resp[nptr++];
                if (!lab) break;
                if ((lab & 0xC0) == 0xC0) {
                    if (nptr >= rlen) break;
                    nptr = ((lab & 0x3F) << 8) | (unsigned char)resp[nptr];
                    continue;
                }
                if (!first) name[nlen++] = '.';
                if (nptr + lab > rlen) break;
                memcpy(name + nlen, resp + nptr, lab);
                nlen += lab; nptr += lab; first = false;
            }
            name[nlen] = '\0';
            char *dot = strstr(name, ".local");
            if (dot) *dot = '\0';
            if (name[0]) {
                strncpy(out, name, outLen - 1);
                out[outLen - 1] = '\0';
                return true;
            }
        }
        rpos += rdlen;
    }
    return false;
}

// ─── Host Thread: ARP then resolve (single pass per host) ────────────────────

struct HostArg {
    DWORD       ipNet;   // network byte order
    ScanResult *result;
};

static DWORD WINAPI hostThread(LPVOID param) {
    HostArg    *a   = (HostArg *)param;
    ScanResult *res = a->result;
    ULONG macLen = 6;

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

static bool parseCIDR(const char *cidr, DWORD *netHost, int *prefix) {
    char buf[40];
    strncpy(buf, cidr, 39); buf[39] = '\0';
    char *slash = strchr(buf, '/');
    if (!slash) return false;
    *slash = '\0';
    *prefix = atoi(slash + 1);
    if (*prefix < 1 || *prefix > 30) return false;
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return false;
    *netHost = ntohl(a.s_addr);
    return true;
}

static int runScan(const char *subnet, const char *outFile) {
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

    DWORD mask  = (~0u << (32 - prefix));
    DWORD first = (netHost & mask) + 1;
    DWORD last  = (netHost | ~mask) - 1;
    if (first > last) { fprintf(stderr, "Subnet too small to scan.\n"); return 1; }

    DWORD total = last - first + 1;
    printf("Scanning %s (%lu hosts)...\n", subnet, (unsigned long)total);

    std::vector<ScanResult> results(total);
    for (auto &r : results) { r.alive = false; memset(r.mac, 0, 6); r.hostname[0] = '\0'; }

    // Each thread does ARP + name resolution.
    // 15s batch timeout: covers ARP (~2s) + DNS + NetBIOS + mDNS (~5s) + margin.
    const DWORD BATCH    = 256;
    const DWORD TIMEOUT  = 15000;

    for (DWORD base = 0; base < total; base += BATCH) {
        DWORD bsz = (base + BATCH <= total) ? BATCH : total - base;

        std::vector<HANDLE>  handles(bsz);
        std::vector<HostArg> args(bsz);

        for (DWORD j = 0; j < bsz; j++) {
            DWORD i        = base + j;
            results[i].ip  = first + i;
            args[j].ipNet  = htonl(first + i);
            args[j].result = &results[i];
            handles[j]     = CreateThread(nullptr, 0, hostThread, &args[j], 0, nullptr);
        }
        for (DWORD j = 0; j < bsz; j += MAXIMUM_WAIT_OBJECTS) {
            DWORD end = (j + MAXIMUM_WAIT_OBJECTS < bsz) ? j + MAXIMUM_WAIT_OBJECTS : bsz;
            WaitForMultipleObjects(end - j, &handles[j], TRUE, TIMEOUT);
        }
        for (DWORD j = 0; j < bsz; j++) CloseHandle(handles[j]);

        printf("  Progress: %lu / %lu\r",
               (unsigned long)(base + bsz), (unsigned long)total);
        fflush(stdout);
    }
    printf("  Progress: %lu / %lu\n", (unsigned long)total, (unsigned long)total);

    // ── Write HTML report ──
    FILE *f = fopen(outFile, "w");
    if (!f) { fprintf(stderr, "Cannot write: %s\n", outFile); return 1; }

    time_t now = time(nullptr);
    char ts[64];
    strftime(ts, sizeof(ts), "%B %d, %Y &mdash; %H:%M:%S", localtime(&now));

    int alive = 0;
    for (const auto &r : results) if (r.alive) alive++;

    fprintf(f,
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"<meta charset=\"UTF-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<title>Subnet Scan &mdash; %s</title>\n"
"<style>\n"
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
"footer{text-align:center;padding:1.2rem;color:#484f58;font-size:.75rem;border-top:1px solid #21262d}\n"
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
        subnet, subnet, ts, (unsigned long)total, alive, (int)total - alive);

    int n = 1;
    for (const auto &r : results) {
        if (!r.alive) continue;
        struct in_addr a; a.s_addr = htonl(r.ip);
        char ipbuf[INET_ADDRSTRLEN], macbuf[18];
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
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

// ─── Adapter List (original functionality) ───────────────────────────────────

static void printVersion() {
    fputs("gip " GIP_VERSION " (built " __DATE__ ")\n", stdout);
}

static void printHelp() {
    printVersion();
    fputs(
        "\nUsage: gip [options]\n"
        "\n"
        "Options:\n"
        "  -6             Show both IPv4 and IPv6 addresses (default: IPv4 only)\n"
        "  -L             Include the Loopback adapter (hidden by default)\n"
        "  -n             Disable colored output\n"
        "  -scan <CIDR>   Scan a subnet and save IP/MAC/hostname report as HTML\n"
        "                 Example: gip -scan 192.168.1.0/24\n"
        "  -o <file>      Output HTML filename for -scan\n"
        "                 (default: GIP-Scan_YYYY-MM-DD_HH-MM-SS.html)\n"
        "  -v             Show version\n"
        "  -help          Show this help message\n"
        "  -?             Show this help message\n", stdout);
}

int main(int argc, char *argv[]) {
    bool        showIPv6   = false;
    bool        showLoop   = false;
    bool        useColor   = true;
    bool        doScan     = false;
    const char *scanSubnet = nullptr;
    const char *outFile    = nullptr;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "-6")    == 0) showIPv6 = true;
        else if (strcmp(argv[i], "-n")    == 0) useColor = false;
        else if (strcmp(argv[i], "-L")    == 0) showLoop = true;
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

    if (doScan) {
        exitCode = runScan(scanSubnet, outFile);
        WSACleanup();
        return exitCode;
    }

    // ── List local adapters ──

    if (useColor) {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(hOut, &mode))
                useColor = SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
            else
                useColor = false;
        } else {
            useColor = false;
        }
    }

    const char *yellow = useColor ? "\033[33m" : "";
    const char *cyan   = useColor ? "\033[36m" : "";
    const char *reset  = useColor ? "\033[0m"  : "";

    ULONG family = showIPv6 ? AF_UNSPEC : AF_INET;
    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES addrs = nullptr;
    DWORD result;
    int   retries = 0;

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
        char ip[INET6_ADDRSTRLEN], adapterName[256], buf[4096];
        int  len = snprintf(buf, sizeof(buf), "\n");

        for (PIP_ADAPTER_ADDRESSES ad = addrs; ad; ad = ad->Next) {
            if (ad->OperStatus != IfOperStatusUp) continue;
            if (!showLoop && ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

            bool printed = false;

            for (PIP_ADAPTER_UNICAST_ADDRESS ua = ad->FirstUnicastAddress; ua; ua = ua->Next) {
                SOCKADDR *sa = ua->Address.lpSockaddr;
                if (!sa) continue;

                const char *label; void *addrPtr;
                if      (sa->sa_family == AF_INET)
                    { label = "  IPv4: "; addrPtr = &((sockaddr_in  *)sa)->sin_addr; }
                else if (sa->sa_family == AF_INET6)
                    { label = "  IPv6: "; addrPtr = &((sockaddr_in6 *)sa)->sin6_addr; }
                else continue;

                inet_ntop(sa->sa_family, addrPtr, ip, sizeof(ip));

                if (!printed) {
                    WideCharToMultiByte(CP_UTF8, 0, ad->FriendlyName, -1,
                                        adapterName, sizeof(adapterName), nullptr, nullptr);
                    len += snprintf(buf + len, sizeof(buf) - len,
                                    "%sAdapter: %s%s%s%s\n",
                                    yellow, reset, cyan, adapterName, reset);
                    printed = true;
                }
                len += snprintf(buf + len, sizeof(buf) - len, "%s%s\n", label, ip);
                if ((size_t)len >= sizeof(buf) - 256) { fwrite(buf, 1, len, stdout); len = 0; }
            }
            if (printed) len += snprintf(buf + len, sizeof(buf) - len, "\n");
        }
        if (len > 0) fwrite(buf, 1, len, stdout);
    }

done:
    free(addrs);
    WSACleanup();
    return exitCode;
}
