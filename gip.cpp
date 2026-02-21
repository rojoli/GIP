#include <cstdio>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "ws2_32")

void printHelp() {
    fputs(
        "Usage: gip [options]\n"
        "\n"
        "Options:\n"
        "  -6      Show both IPv4 and IPv6 addresses (default: IPv4 only)\n"
        "  -L      Include the Loopback adapter (hidden by default)\n"
        "  -n      Disable colored output\n"
        "  -help   Show this help message\n"
        "  -?      Show this help message\n", stdout);
}

int main(int argc, char *argv[]) {
    bool showIPv6 = false;
    bool showLoopback = false;
    bool useColor = true;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-6") == 0) {
            showIPv6 = true;
        } else if (strcmp(argv[i], "-n") == 0) {
            useColor = false;
        } else if (strcmp(argv[i], "-L") == 0) {
            showLoopback = true;
        } else if (strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "-?") == 0) {
            printHelp();
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            printHelp();
            return 1;
        }
    }

    if (useColor) {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            if (GetConsoleMode(hOut, &mode)) {
                if (!SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
                    useColor = false;
            } else {
                useColor = false;
            }
        } else {
            useColor = false;
        }
    }

    const char *yellow = useColor ? "\033[33m" : "";
    const char *cyan   = useColor ? "\033[36m" : "";
    const char *reset  = useColor ? "\033[0m"  : "";

    ULONG family = showIPv6 ? AF_UNSPEC : AF_INET;
    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES addresses = nullptr;
    DWORD result;
    int retries = 0;
    const int maxRetries = 3;

    do {
        addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
        if (!addresses) {
            fputs("Memory allocation failed\n", stderr);
            return 1;
        }
        result = GetAdaptersAddresses(family, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &bufLen);
        if (result == ERROR_BUFFER_OVERFLOW) {
            free(addresses);
            addresses = nullptr;
            retries++;
        }
    } while (result == ERROR_BUFFER_OVERFLOW && retries < maxRetries);

    if (result != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses failed: %lu\n", result);
        free(addresses);
        return 1;
    }

    char ip[INET6_ADDRSTRLEN];
    char adapterName[256];
    char buf[4096];
    int len = 0;

    len += snprintf(buf + len, sizeof(buf) - len, "\n");

    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp)
            continue;

        if (!showLoopback && adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        bool printed = false;

        for (PIP_ADAPTER_UNICAST_ADDRESS addr = adapter->FirstUnicastAddress; addr; addr = addr->Next) {
            SOCKADDR *sa = addr->Address.lpSockaddr;
            if (!sa) continue;

            const char *label;
            void *addrPtr;

            if (sa->sa_family == AF_INET) {
                label = "  IPv4: ";
                addrPtr = &((sockaddr_in *)sa)->sin_addr;
            } else if (sa->sa_family == AF_INET6) {
                label = "  IPv6: ";
                addrPtr = &((sockaddr_in6 *)sa)->sin6_addr;
            } else {
                continue;
            }

            inet_ntop(sa->sa_family, addrPtr, ip, sizeof(ip));

            if (!printed) {
                WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, adapterName, sizeof(adapterName), nullptr, nullptr);
                len += snprintf(buf + len, sizeof(buf) - len, "%sAdapter: %s%s%s%s\n", yellow, reset, cyan, adapterName, reset);
                printed = true;
            }

            len += snprintf(buf + len, sizeof(buf) - len, "%s%s\n", label, ip);

            if ((size_t)len >= sizeof(buf) - 256) {
                fwrite(buf, 1, len, stdout);
                len = 0;
            }
        }

        if (printed)
            len += snprintf(buf + len, sizeof(buf) - len, "\n");
    }

    if (len > 0)
        fwrite(buf, 1, len, stdout);

    free(addresses);
    return 0;
}
