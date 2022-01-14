#!/usr/bin/env python
import sys
import time
import random
from subprocess import Popen, PIPE
import re
from scapy.all import sendp, get_if_list, get_if_hwaddr,sendpfast
from scapy.all import Ether, IP, UDP, TCP,Raw,conf

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        exit(1)
    return iface

def get_dst_mac(ip):
    try:
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = pid.communicate()[0]
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0] #not know how
        return mac
    except:
        return None

#usage python sendcheck.py dst_ip send_packet_num

def main():


    iface = get_if()

    seen_timestamps=set()
    current_time=""
    last_time=0
    total_sent=0
    all_pkt_id=set()
    total_packets = int(sys.argv[2])
    for i in range(0, total_packets):
        all_pkt_id.add(i)
    ether_dst='{0:0{1}X}'.format(0,12)
    ether_src='{0:0{1}X}'.format(0,12)
    ether_dst=':'.join([ether_dst[i:i+2] for i in range(0, len(ether_dst), 2)])
    receiver_ip = sys.argv[1]

    pkt_list=[]
    for pkt_id in all_pkt_id:
        pkt =  Ether(src=ether_src, dst=ether_dst)
        pkt = pkt /IP(dst=receiver_ip,ttl=255,id=pkt_id, tos=4)
        #pkt = pkt /IP(dst=receiver_ip,ttl=255,id=pkt_id) / UDP()
        pkt_list.append(pkt)
        total_sent=total_sent+1
    start_time = time.time()
    sendp(pkt_list,iface=iface,verbose=False, inter=0.1)
    end_time = time.time()
    print(end_time - start_time)
if __name__ == '__main__':
    main()
