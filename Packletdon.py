#imports
from pyfiglet import Figlet
from scapy.all import * #need scapy for network control/access 
import sys

#create banner
f = Figlet(font='slant')
print(f.renderText('Packletdon'))

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

if __name__ == "__main__":
  enter_and_read_pcap()
