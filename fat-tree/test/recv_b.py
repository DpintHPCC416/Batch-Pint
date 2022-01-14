import time
import zlib
from scapy.all import *
import multiprocessing
import sys


class Dpint(Packet):
    name = "Dpint"
    fields_desc = [ByteField("protocol", 0),ShortField("hop", 0),ShortField("task", 0),IntField("value",0)]


def listener(queue):
    k=0
    total_packets=0
    distance_metric={}
    fw=open("result","w")
    fw.close()
    while True:
        data=queue.get()
        src=data[0]
        dst=data[1]
        hop = data[2]
        task=data[3]
        value = data[4]
        total_packets=total_packets+1
        if total_packets==1:
            start_time=time.time()
        fw=open("result","a")
        fw.write(str(total_packets)+","+str(src)+","+str(dst)+","+str(hop)+","+str(task)+","+str('{0:#08x}'.format(value)) + "\n")
        fw.close()
    return


def parent_callback(queue):
    def pkt_callback(pkt):
        ip_header=pkt.getlayer(IP)
        ecn=ip_header.tos
        pkt_id=ip_header.id
        ttl=ip_header.ttl
        src = ip_header.src
        dst = ip_header.dst
        dpint=Dpint(str(pkt.getlayer(IP).payload))
        hop=dpint.hop
        task=dpint.task
        value = dpint.value
        if ecn==1:
            queue.put((src,dst,hop,task,value))
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
