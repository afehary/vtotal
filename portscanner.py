#!/usr/bin/env python3
import socket
from utils import timefunc

#Function to validate ip addresses
def validate_ip(ip_addresses):
    # Split and clean the IP addresses by stripping spaces
    ips = [ip.strip() for ip in ip_addresses.split(',')]
    for ip in ips:
        try:
            socket.inet_aton(ip)  # Check if valid IP address
        except socket.error:
            return None  # Return None if any IP is invalid
    return ips  # Return cleaned IP addresses if all are valid


# Fuction to validate port, port range, or group of ports
def valid_ports(ports_input, is_range=False):
    if is_range:
        try:
            start_port, end_port = map(int, ports_input.replace(' ', '').split('-'))  # Remove spaces in range
            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                return (start_port, end_port)
            else:
                return None
        except ValueError:
            return None
    else:
        try:
            ports = list(map(int, [port.strip() for port in ports_input.split(',')]))  # Strip spaces around each port
            if all(1 <= port <= 65535 for port in ports):
                return ports
            else:
                return None
        except ValueError:
            return None


# Reusable function to check if a port is open and optionally return the banner (service version)
def is_port_open(ip, port, grab_banner=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))

        if result == 0:  # Port is open
            banner = None
            if grab_banner:
                # Try to grab the service banner (for version detection)
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')  # HTTP example, adjust for other services
                    banner = sock.recv(1024).decode().strip()  # Receive banner (up to 1024 bytes)
                except Exception as e:
                    banner = None  # Failed to grab banner, return None
            sock.close()
            return True, banner
        else:
            sock.close()
            return False, None
    except Exception as e:
        return False, None

#fuction to scan ports# Function to scan ports
@timefunc
def scan(ips, ports):
    print("Scanning..")
    for ip in ips:
        for port in ports:
            is_open, _ = is_port_open(ip, port)  # Unpack the tuple
            if is_open:
                print(f"IP: {ip} | Port {port} is open")
            else:
                continue


# Function to take command-line input interactively
def get_input():
    # Prompt user for IP addresses
    get_ips = input("Enter IP address(es) separated by commas: ")
    ips = validate_ip(get_ips)
    if not ips:
        print("Invalid IP address format!")
        return None, None

    # Prompt user for scan option
    scan_option = input("Enter 1 to scan a specific port, 2 to scan a range of ports, 3 to scan two or more ports, 4 to scan all ports: ")

    if scan_option == '1':
        port_input = input("Enter a specific port (1-65535): ")
        ports = valid_ports(port_input, is_range=False)
        if not ports:
            print("Invalid port!")
            return None, None
        return ips, ports

    elif scan_option == '2':
        port_range = input("Enter port range (e.g., 10-800): ")
        ports = valid_ports(port_range, is_range=True)
        if not ports:
            print("Invalid port range!")
            return None, None
        start_port, end_port = ports
        return ips, range(start_port, end_port + 1)

    elif scan_option == '3':
        port_group = input("Enter a comma-separated group of ports: ")
        ports = valid_ports(port_group, is_range=False)
        if not ports:
            print("Invalid ports!")
            return None, None
        return ips, ports

    elif scan_option == '4':
        return ips, range(1, 65536)

    else:
        print("Invalid option")
        return None, None
    

def main():
    ips, ports = get_input()
    if ips and ports:
        scan(ips, ports)

            
if __name__ == '__main__':
    main()