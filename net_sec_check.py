import subprocess
import nmap
import socket
import netifaces

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def scan_network():
    local_ip = get_local_ip()
    network = local_ip.rsplit('.', 1)[0] + '.0/24'
    
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    return hosts_list

def check_open_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')
    open_ports = []
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            open_ports.append(port)
    return open_ports

def get_default_gateway():
    gateways = netifaces.gateways()
    return gateways['default'][netifaces.AF_INET][0]

def main():
    print("Welcome to NetSecCheck!")
    print("Scanning your local network...")
    
    hosts = scan_network()
    
    print("\nDevices found on the network:")
    for host, status in hosts:
        print(f"IP: {host}\tStatus: {status}")
    
    local_ip = get_local_ip()
    gateway_ip = get_default_gateway()
    
    print(f"\nYour IP: {local_ip}")
    print(f"Gateway IP: {gateway_ip}")
    
    print("\nChecking open ports on your device...")
    open_ports = check_open_ports(local_ip)
    if open_ports:
        print("Open ports found:")
        for port in open_ports:
            print(f"Port {port} is open")
    else:
        print("No open ports found")
    
    print("\nSecurity Recommendations:")
    print("1. Ensure your router firmware is up to date")
    print("2. Use a strong Wi-Fi password")
    print("3. Enable WPA3 encryption if available")
    print("4. Disable WPS")
    print("5. Consider setting up a guest network for visitors")
    print("6. Regularly check for and install updates on all connected devices")

if __name__ == "__main__":
    main()
