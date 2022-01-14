import time
import zlib

import scapy.arch
from scapy.all import *
import multiprocessing
import sys

class Dpint(Packet):
    name = "Dpint"
    fields_desc = [ShortField("hop", 0),ShortField("task", 0),IntField("value",0)]


def parent_callback():
    def pkt_callback(pkt):
        ip_header=pkt.getlayer(IP)
        ecn=ip_header.tos
        pkt_id=ip_header.id
        print "get packet %d tos %d" % (pkt_id, ecn)
    return pkt_callback

#usage python recvcheck.py sender_ip send_packet_num
receiver_ip = scapy.arch.get_if_addr('eth0')
sender_ip = sys.argv[1]
total_packets=int(sys.argv[2])
receiver_interface = 'eth0'
result = sniff(iface=receiver_interface, store=1,count=total_packets, prn=parent_callback(),filter="dst net %s and src net %s and ip[1] == 5" % (receiver_ip, sender_ip))

