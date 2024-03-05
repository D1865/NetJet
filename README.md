# NetJet
Dive into network discovery with NetJet
# NetJet: The Network Explorer


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


## Installation & Usage

### `Clone the repo`
### `cd NetJet`
### `chmod +x netjet.py`
`python netjet.py --ip-ranges "192.168.1.1-192.168.1.50,10.0.0." --ports "22,80,443"`

`python netjet.py -h`



## Contributing
Contributions to NetJet are welcome! If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

## Don't forget to give the project a star! Thanks again!

# License
## Distributed under the MIT License. See LICENSE for more information.

# Acknowledgments
- The Scapy community for an amazing packet manipulation tool.
- Nmap for the powerful OS detection capabilities.
- IEEE for maintaining the OUI database.
