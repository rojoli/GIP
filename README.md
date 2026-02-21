# GIP - Get IP Addresses

A lightweight Windows command-line tool that lists IP addresses of all active network adapters.

## Features

- Displays IPv4 addresses by default
- Colored output (adapter names highlighted) with graceful fallback on older systems
- Optional IPv6 display
- Loopback adapter hidden by default
- Compatible with Windows 10, Server 2016, Server 2019, and Server 2022

## Usage

```
gip [options]
```

### Options

| Switch  | Description                                          |
|---------|------------------------------------------------------|
| `-6`    | Show both IPv4 and IPv6 addresses (default: IPv4 only) |
| `-L`    | Include the Loopback adapter (hidden by default)     |
| `-n`    | Disable colored output                               |
| `-help` | Show help message                                    |
| `-?`    | Show help message                                    |

### Example Output

```
Adapter: Ethernet
  IPv4: 192.168.1.100

Adapter: Wi-Fi
  IPv4: 10.0.0.50
```

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

- `IPHLPAPI.DLL` — `GetAdaptersAddresses`
- `WS2_32.dll` — `inet_ntop`
- `KERNEL32.dll` — Console mode, `WideCharToMultiByte`
