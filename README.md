# GIP - Get IP Addresses

A lightweight Windows command-line tool that lists IP addresses of all active network adapters and can scan subnets for active hosts.

## Features

- Displays IPv4 addresses by default
- Colored output (adapter names highlighted) with graceful fallback on older systems
- Optional IPv6 display
- Loopback adapter hidden by default
- Subnet scanner: ARP-based scan returning IP and MAC addresses for all active hosts
- HTML report output with dark-themed, styled table
- Compatible with Windows 10, Server 2016, Server 2019, and Server 2022

## Usage

```
gip [options]
```

### Options

| Switch          | Description                                              |
|-----------------|----------------------------------------------------------|
| `-6`            | Show both IPv4 and IPv6 addresses (default: IPv4 only)   |
| `-L`            | Include the Loopback adapter (hidden by default)         |
| `-n`            | Disable colored output                                   |
| `-scan <CIDR>`  | Scan a subnet and generate an HTML IP/MAC/hostname report |
| `-o <file>`     | Output filename for `-scan` (default: `GIP-Scan_YYYY-MM-DD_HH-MM-SS.html`) |
| `-v`            | Show version and build date                              |
| `-help`         | Show help message                                        |
| `-?`            | Show help message                                        |

### Example Output

```
Adapter: Ethernet
  IPv4: 192.168.1.100

Adapter: Wi-Fi
  IPv4: 10.0.0.50
```

### Subnet Scan

Scan an entire subnet and save a styled HTML report of all active hosts with their MAC addresses:

```
gip -scan 192.168.1.0/24
gip -scan 10.0.0.0/24 -o network_report.html
```

The report includes:
- Summary stats (total hosts scanned, active, no response)
- Table of each responding host: IP address and MAC address
- Dark-themed HTML — open directly in any browser

> **Note:** Subnet scanning uses ARP and requires the tool to be run on the same Layer 2 network segment as the targets. Hosts on routed subnets will not respond to ARP.

### Note

In PowerShell, `gip` may resolve to the built-in `Get-NetIPAddress` alias. Use `.\gip.exe` or `gip.exe` to run this tool explicitly.

## Building

### Requirements

- **Compiler**: g++ (MinGW-w64 via MSYS2, ucrt64 toolchain)
- **Tested with**: g++ 15.2.0 (Rev8, Built by MSYS2 project)
- **Target**: x86_64-w64-mingw32

### Install MSYS2 and g++

1. Install MSYS2 from https://www.msys2.org/
2. Open the MSYS2 terminal and install the ucrt64 toolchain:
   ```
   pacman -S mingw-w64-ucrt-x86_64-gcc
   ```
3. Add `C:\msys64\ucrt64\bin` to your system PATH

### Compile

```
g++ gip.cpp -o gip.exe -Os -s -liphlpapi -lws2_32
```

| Flag           | Purpose                                    |
|----------------|--------------------------------------------|
| `-Os`          | Optimize for binary size                   |
| `-s`           | Strip debug symbols (smaller executable)   |
| `-liphlpapi`   | Link Windows IP Helper API                 |
| `-lws2_32`     | Link Winsock2 library                      |

### Windows API Dependencies

- `IPHLPAPI.DLL` — `GetAdaptersAddresses`, `SendARP`
- `WS2_32.dll` — `inet_ntop`
- `KERNEL32.dll` — Console mode, `WideCharToMultiByte`, `CreateThread`
