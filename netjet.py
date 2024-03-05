import subprocess
import sys
import ipaddress
from scapy.all import ARP, Ether, srp, IP, sr1, TCP

# Global Variables
VERBOSE = False
OUI_DATABASE_PATH = "oui.txt"

def banner():
    print(r"""
  __   __     ______     ______     __  __     ______     __   __    
 /\ "-.\ \   /\  __ \   /\  ___\   /\ \/\ \   /\  ___\   /\ "-.\ \   
 \ \ \-.  \  \ \ \/\ \  \ \ \____  \ \ \_\ \  \ \ \__ \  \ \ \-.  \  
  \ \_\\"\_\  \ \_____\  \ \_____\  \ \_____\  \ \_____\  \ \_\\"\_\ 
   \/_/ \/_/   \/_____/   \/_____/   \/_____/   \/_____/   \/_/ \/_/ 
                                                                     
                          NetJet: Your Network Explorer
                          Created By Daniel Hall
                          Press Ctrl+C to Exit
""")

def load_oui_database(oui_database_path):
    oui_dict = {}
    try:
        with open(oui_database_path, 'r') as file:
            for line in file:
                if "(base 16)" in line:
                    parts = line.split("(base 16)")
                    oui = parts[0].strip().replace("-", ":").lower()
                    manufacturer = parts[1].strip()
                    oui_dict[oui] = manufacturer
    except FileNotFoundError:
        print("OUI database file not found. Please ensure oui.txt is in the script's directory.")
        sys.exit(1)
    return oui_dict

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=VERBOSE)
    if ans:
        return ans[0][1].src
    return None

def manufacturer_lookup(mac, oui_dict):
    oui = mac.lower()[:8]
    return oui_dict.get(oui, "Unknown Manufacturer")

def os_detection(ip):
    try:
        nmap_scan = subprocess.check_output(["nmap", "-O", "--osscan-guess", ip], stderr=subprocess.STDOUT).decode()
        if VERBOSE:
            print("Nmap OS detection output:")
            print(nmap_scan)
        else:
            for line in nmap_scan.split("\n"):
                if "OS details" in line or "Running" in line:
                    return line.strip()
    except subprocess.CalledProcessError:
        return "Nmap OS detection failed"
    return "OS not detected"

def scan_host(ip, ports, oui_dict):
    print(f"\nScanning host {ip}...")
    mac = get_mac(ip)
    if mac:
        manufacturer = manufacturer_lookup(mac, oui_dict)
        os_info = os_detection(ip)
        print(f"Host {ip} is up. MAC: {mac}, Manufacturer: {manufacturer}, OS Info: {os_info}")
        for port in ports:
            portscan = sr1(IP(dst=ip)/TCP(dport=port), timeout=10, verbose=VERBOSE)
            if portscan and portscan.haslayer(TCP):
                if portscan[TCP].flags == 0x12:
                    print(f"Port {port} is open")
                    sr1(IP(dst=ip)/TCP(dport=port, flags='R'), timeout=10, verbose=VERBOSE)
    else:
        print(f"Host {ip} seems down.")

def parse_ports(ports_str):
    ports = []
    parts = ports_str.split(',')
    for part in parts:
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports

def parse_ip_ranges(ip_ranges_str):
    ip_list = []
    for ip_range in ip_ranges_str.split(','):
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            start_ip = ipaddress.ip_address(start_ip)
            end_ip = ipaddress.ip_address(end_ip)
            while start_ip <= end_ip:
                ip_list.append(str(start_ip))
                start_ip += ipaddress.IPv4Address(1)
        else:  # Handle single subnet e.g., 192.168.1.
            for ip in ipaddress.ip_network(f"{ip_range}0/24", strict=False).hosts():
                ip_list.append(str(ip))
    return ip_list

def print_help():
    print("""
NetJet Usage:
  -h, --help          Show this help message.
  -v, --verbose       Enable verbose output.
  --ip-ranges         Specify IP ranges or subnets to scan (e.g., "192.168.1.1-192.168.1.50,192.168.2.").
  --ports             Specify ports to scan, separated by commas or ranges (e.g., "22,80,443,1000-2000").

Examples:
  Scan specific IP ranges: python netjet.py --ip-ranges "192.168.1.1-192.168.1.50" --ports "22,80"
  Scan an entire subnet: python netjet.py --ip-ranges "192.168.1." --ports "22,80,443"

Press Ctrl+C to Exit
    """)

def main():
    global VERBOSE
    banner()
    if "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        return
    if "-v" in sys.argv or "--verbose" in sys.argv:
        VERBOSE = True

    if "--ip-ranges" in sys.argv:
        ip_ranges_index = sys.argv.index("--ip-ranges") + 1
        ip_ranges_str = sys.argv[ip_ranges_index]
        ip_ranges = parse_ip_ranges(ip_ranges_str)
    else:
        print("IP ranges (--ip-ranges) are required.")
        return

    if "--ports" in sys.argv:
        ports_index = sys.argv.index("--ports") + 1
        ports_str = sys.argv[ports_index]
        ports = parse_ports(ports_str)
    else:
        print("Ports (--ports) are required.")
        return

    oui_dict = load_oui_database(OUI_DATABASE_PATH)
    
    for ip in ip_ranges:
        scan_host(ip, ports, oui_dict)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nNetJet terminated. Goodbye!")
