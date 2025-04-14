# Windows Privilege Escalation Tool

A Windows privilege escalation utility that demonstrates token manipulation techniques.

## Features

- Process token manipulation
- Session-based process identification
- Privilege elevation
- Command prompt spawning with elevated privileges

## Requirements

- Windows operating system
- Administrator privileges for full functionality
- Visual Studio or compatible C++ compiler

## Building

```bash
# Using Visual Studio
msbuild Privilege-Escalation.sln

# Using g++
g++ main.cpp -o privilege-escalation.exe
```

## Usage

```bash
privilege-escalation.exe [options]

Options:
  --help        Show this help message
  --session     Specify target session ID (default: 0)
  --process     Specify target process name
```

## Security Considerations

This tool is for educational purposes only. Use responsibly and only on systems you own or have explicit permission to test.

## License

MIT License
