# Topology:

​	Briefly, we constructed a linear network topology consisting of  switches and  hosts. For 3 switches, the topology is shown in this figure:

![topology1](.\topology1.png)

# EVNIRONMENT:

- p4-utils: [p4-utils](https://github.com/nsg-ethz/p4-utils)

- python package dependency: networkx, scapy
- python 2.7 may be needed

# Files:

​	We have built a folder for each of the four scheduling methods, each folder has a similar structure.

​	Take the batch folder as an example: 

- p4src/dpint.p4: dpint file written by p4

- utils/recv.py, send.py: used by one host to send packets and another host to receive packets with analyzing. You also need to change the config file to change configuration

- initial_entry.py: initialize the static entries when starting the switch. it will generate switch_CLI file in rules folder.

  - rules: the command line file to instruct the switch to add some entries. For more command, you can see [runtime_cli](https://github.com/p4lang/behavioral-model/blob/main/docs/runtime_CLI.md). If you need to see more in p4switch, you need open a new bash window, code `simple_switch_CLI --thrift-port p` , where p is thrift port of the switch. You can find p when start swithes in mininet by input command `printNetInfo`. For more infomation of switch, try input command `help command`. For example, `show_tables` will see all the tables in switch.`table_dump tbl` will show all the entries in tbl.

- topo_allocator.py, p4_app.json, p4sample_app.json: use the topo_allocator.py to generate the p4_app.json, which is used by p4-utils to initialize the topology and some configuration. you can see more about it in [p4-utils](https://github.com/nsg-ethz/p4-utils)

- result: the result recieved by utils/recv.py.

# Steps to run this demo

- Create topology:
 to generate topo(`p4_app.json`). num represents number of switches, 3 for example.

```
python topo_allocator.py num
```

- Start Mininet.

  Start Mininet with the newly constructed topology.

```
sudo p4run --config p4app.json
```

- in mininet, `xterm h0 h2` to call the bash window. In h2, `python utils/recv.py` to receive. In h0, `python utils/send.py` to send. In configure, we need to set `receive_ip` to 10.0.0.2 and `send_ip` to 10.0.0.0. Also, you can change `total_packets` to control how many sender will send.

# For Debug:

- The log information would be generated in folder  `log`.
- the packet captured information for each switch would be put in the folder` pcap`. Open with wireshark.