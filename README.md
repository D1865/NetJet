# NetJet
Dive into network discovery with NetJet
# NetJet: The Network Explorer

![NetJet Banner](banner.png)

Dive into network discovery with `NetJet`, a powerful Python tool designed for network administrators, security professionals, and anyone curious about the devices on their network. `NetJet` simplifies the task of scanning IP ranges, identifying open ports, detecting operating systems, and much more, all with an easy-to-use command-line interface.

## Features

- **Multiple IP Range Scanning**: Effortlessly scan non-contiguous IP ranges or entire subnets.
- **Specific Port Scanning**: Pinpoint scanning to specific ports or ranges for detailed exploration.
- **Verbose Output**: Get detailed insights into the scanning process and findings.
- **OS Detection**: Utilize Nmap for advanced operating system detection.
- **Manufacturer Identification**: Identify device manufacturers using the local IEEE OUI database.

## Getting Started

### Prerequisites

- Python 3.x
- Scapy
- Nmap
- Requests (for potential future enhancements)

Navigate to the NetJet directory:
sh
Copy code
cd netjet
Ensure you have the necessary tools installed (Python 3, Scapy, Nmap).
Usage
To use NetJet, run the script with the required options:

sh
Copy code
python netjet.py --ip-ranges "192.168.1.1-192.168.1.50,10.0.0." --ports "22,80,443"
For detailed help and more examples, use:

sh
Copy code
python netjet.py -h
