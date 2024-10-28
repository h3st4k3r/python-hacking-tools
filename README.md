# Port Scanner

**Port Scanner** is a fast and customizable Python port scanner designed to identify open TCP and UDP ports and retrieve basic version information from services when available. This tool is intended for ethical hackers and security professionals who need a quick overview of active services on a target machine.

## Features
- Scans all 65,535 ports on both TCP and UDP.
- Displays service version information if the service provides a banner.
- Custom user-agent header (`h3st4k3r-port-scan`) to identify scan requests.
- Summary table of open ports at the end of the scan.

## Usage
To run the script, provide an IP address as a parameter. If no IP address is provided, the script will display usage instructions.

```bash
python port-scan.py <IP>
```

![Output](https://github.com/user-attachments/assets/ca60bfae-c836-4984-b88b-4a1c64f1c036)

