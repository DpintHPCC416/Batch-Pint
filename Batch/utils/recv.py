import time
import zlib
from scapy.all import *
import multiprocessing
import sys


class Dpint(Packet):
    name = "Dpint"
    fields_desc = [ByteField("hop", 0),ShortField("task", 0)]


def listener(queue,stop_total_packets):
    k=0
    total_packets=0
    distance_metric={}
    fw=open("result","w")
    fw.close()
    while True:
        data=queue.get()
        k=data[0]
        pkt_id=data[1]
        task=data[2]
        total_packets=total_packets+1
        if total_packets==1:
            start_time=time.time()
        fw=open("result","a")
        fw.write(str(total_packets)+","+str(k)+","+str(pkt_id)+","+str('{0:#016b}'.format(task)) + "\n")
        fw.close()
    return



def parent_callback(queue):
    def pkt_callback(pkt):
        ip_header=pkt.getlayer(IP)
        ecn=ip_header.tos
        pkt_id=ip_header.id
        ttl=ip_header.ttl
        dpint=Dpint(str(pkt.getlayer(IP).payload))
        hop=dpint.hop
        task=dpint.task
        if ecn==1:
            queue.put((hop,pkt_id,task))
    return pkt_callback

manager = multiprocessing.Manager()
queue = manager.Queue()
pool = multiprocessing.Pool(1)

f=open("config","r")
for line in f:
    line=line.strip().split("=")
    type=line[0]
    data=line[1]
    if type=="max_bit_range":
        max_bit_range=int(data)
    if type=="global_hash_range":
        global_hash_range=int(data)
    if type=="receiver_interface":
        receiver_interface=data
    if type=="receiver_ip":
        receiver_ip=data
    if type=="common_log":
        common_log=data
    if type=="total_packets":
        total_packets=int(data)
    if type=="iterations":
        iterations=int(data)
f.close()


watcher = pool.apply_async(listener,(queue,total_packets*iterations))
sniff(iface=receiver_interface, prn=parent_callback(queue), filter="dst net "+receiver_ip, store=0)
