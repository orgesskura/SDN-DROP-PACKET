## Part 1: Simple L4 firewall in OpenFlow. (10%)

Suppose you are a network administrator in a small office.
You want to prevent TCP connections from being initiated by external hosts, while allowing
for those initiated by the internal hosts. Fortunately you
have deployed an OpenFlow switch to which all the internal hosts connect.  Being
inspired by this scenario, implement an OpenFlow controller to achieve this
feature. You use [Ryu](https://ryu-sdn.org/) to implement an OpenFlow controller in
Python and [Mininet](http://mininet.org/) to emulate a network.

**Specification:**
The emulated network consists of one internal host, one external host and one switch.
The switch has two ports; port 1 and port 2 connect to the internal and external host, respectively.
Your controller
must insert the flow to the switch when observing a TCP-over-IPv4 packet that arrives
at the switch port 1. You can ignore the TCP flags.
Further, when the controller sees a returning packet in this TCP connection
arriving at switch port 2, it must forward this packet to switch port 1 and insert the
corresponding flow to the switch.
These flows must match against input switch port, network layer protocol, source IP address,
destination IP address, transport layer protocol, source port and destination port.
  All the packets that are *not* TCP-over-IPv4 can pass the switch or controller (i.e., forwarded from switch port 1 to 2 and vice versa). You do not have to insert a flow for non-TCP-over-IPv4 packets.
Implement these features by completing `_packet_in_handler()` method in [`l4state.py`](./l4state.py).
Do not remove any existing lines, and do not import any other modules. Also, do not define new class nor methods.

You can test the program in Mininet:
```
vagrant@ubuntu-focal:~$ ryu-manager l4state.py
```
and in another window (the output of `h1 iperf -c h2 -t 2` is based on correctly-implemented [l4state.py](./l4state.py)):
```
vagrant@ubuntu-focal:~$ sudo mn --topo single,2 --mac --controller remote --switch ovsk
*** Creating network
*** Adding controller
Connecting to remote controller at 127.0.0.1:6653
*** Adding hosts:
h1 h2 
*** Adding switches:
s1 
*** Adding links:
(h1, s1) (h2, s1) 
*** Configuring hosts
h1 h2 
*** Starting controller
c0 
*** Starting 1 switches
s1 ...
*** Starting CLI:
mininet> h2 iperf -s &
mininet> h1 iperf -c h2 -t 2
------------------------------------------------------------
Client connecting to 10.0.0.2, TCP port 5001
TCP window size: 85.3 KByte (default)
------------------------------------------------------------
[  3] local 10.0.0.1 port 40252 connected with 10.0.0.2 port 5001
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0- 2.1 sec  10.4 MBytes  42.3 Mbits/sec
mininet> 
```
`h2 iperf -s &` starts an iperf server at h2 connected to the switch port 2.
`h1 iperf -c h2 -t 2` initiates a TCP connection to that iperf server and
generates traffic for 2 second.

### Marking Criteria

1. [l4state.py](./l4state.py) can pass non-TCP-over-IPv4 packets that are sent from host
2 to host 1 and block TCP-over-IPv4 packets that are sent from host 2 to host 1 before seeing any packets sent from host 1 to host 2, which must pass the following test (**4%**):
```
python3.8 -m pytest tests/test_l4state.py::test_l4state1
```
2. [l4state.py](./l4state.py) meet all the requirements in the **Specification** paragraph above, which must pass the following test (**6%**):
```
python3.8 -m pytest tests/test_l4state.py
```
Note that since meeting the first criteria is an intermediate step to meet the second criteria, the possible score is 0%, 4% or 10%.

### Hints

In the `_packet_in_handler`, the first step would be to simply forward all the packets between switch port 1 and 2.
To this end, the code would just substitute `1` or `2` in the `out_port`
variable, and define the `acts` list, which is passed to `OFPPacketOut()`, using this variable, similar to [l2learn.py](./l2learn.py).
At this point the controller already should run without error (although not
satisfying yet the specification of this assignment).
You can test that in the above Mininet environment by `h1 ping -c 1 h2`
and `h2 ping -c 1 h1` (ping generates ICMP packets i.e., non-TCP-over-IPv4) being successful instead of the `iperf` commands (iperf generates TCP traffic).

You will then implement *exceptional* cases for TCP-over-IPv4 packets.
You will first need to identify such a packet, and extract the flow key that is a tuple of `(<srcip>, <dstip>, <srcport>, <dstport>)`.
You can obtain the IPv4 header by `iph = pkt.get_protocols(ipv4.ipv4)`;
`iph` is a list that contains 0 or 1 Ryu IPv4 header object.
Similar, you can obtain the TCP header by `tcph = pkt.get_protocols(tcp.tcp)`.

Then, if the packet comes from port 1, search for the hash table private in the controller, which is `ht`, a `set()` object initiated in `__init__()` method of the `L4State14` class (this is NOT the flow table in the switch); insert the flow key in `ht` if it does not exist. This hash table is used to identify, when the controller receives a TCP-over-IPv4 packet that arrives at switch port 2, whether the corresponding flow has been initiated by the internal host or not.
Then also insert the flow in the switch, so that the controller does not have to process the packets in this TCP connection that arrive at switch port 1.

If the packet comes from port 2 and the corresponding flow entry in `ht`, which
is the four-tuple of the packet with source and destination addresses and ports swapped (remember how the entry has been created based on the packet arriving at port 1), does not exist, it should be dropped, otherwise it should be forwarded to switch port 1 **and** the flow entry is inserted in the switch, again so that the controller does not have to process packets in the same flow (port 2 to 1).
You can drop the packet by specifying `psr.OFPActionOutput(ofp.OFPPC_NO_FWD)` in
the actions list (`acts`).
The sample solution (not provided) consists of 67 lines, but this number is just
a reference, and no need to match.


## Part 2: Port mirroring in OpenFlow (10%)

In another network, you now want to allow all the packets to go through the
switch,
but for every TCP connection initiated by an external host, you want to collect first ten packets coming from the external network.

**Specification:** Your task is to implement this logic by completing `_packet_in_handler()` method in [`l4mirror.py`](./l4mirror.py), using Ryu and Mininet again, but with slightly different network topology where the switch has one more port (port 3) connected to another host, h3, that collects the first ten packets in every TCP connection initiated by an external host.  As in Part 1, h1 is an internal host connected to switch port 1, and h2 is an external host connected to switch port 2.
Your controller must work as follows.
The controller inserts the flow unconditionally when it sees a TCP-over-IPv4 packet coming from port 1 (i.e., sent by the internal host).
Further, it must insert the flow when it sees 10th packet coming from port 2 in the connection, counting from the TCP packet with the SYN flag set and the ACK flag unset; the controller must process the first 10 packets while duplicating and forwarding (i.e., mirroring) these packets to switch port 3 (in addition to forwarding them to port 1).  You do not have to consider timeout of the flows in the switch or flow entries in the controller.
Do not remove any existing lines, and do not import any other modules. Also, do not define new class nor methods.
For testing,  the controller (i.e., `l4mirror.py`) and Mininet will be instantiated as follows (the output from the `h2 iperf -c h1 -t 1` and `h3 pkill tcpdump` is based on the correctly implemented version of [l4mirror.py](./l4mirror.py)):
```
vagrant@ubuntu-focal:~$ ryu-manager l4mirror.py
```
In another window:
```
vagrant@ubuntu-focal:~$ sudo mn --topo single,3 --mac --controller remote --switch ovsk
*** Creating network
*** Adding controller
Connecting to remote controller at 127.0.0.1:6653
*** Adding hosts:
h1 h2 h3 
*** Adding switches:
s1 
*** Adding links:
(h1, s1) (h2, s1) (h3, s1) 
*** Configuring hosts
h1 h2 h3 
*** Starting controller
c0 
*** Starting 1 switches
s1 ...
*** Starting CLI:
mininet> h1 iperf -s &
mininet> h3 tcpdump &
mininet> h2 iperf -c h1 -t 1
------------------------------------------------------------
Client connecting to 10.0.0.1, TCP port 5001
TCP window size: 85.3 KByte (default)
------------------------------------------------------------
[  3] local 10.0.0.2 port 32796 connected with 10.0.0.1 port 5001
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0- 1.0 sec  4.38 GBytes  37.6 Gbits/sec
mininet> h3 pkill tcpdump
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on h3-eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
15:45:53.699831 IP6 fe80::200:ff:fe00:3 > ip6-allrouters: ICMP6, router solicitation, length 16
15:45:53.699804 IP6 fe80::f4a6:4dff:fec8:f51 > ip6-allrouters: ICMP6, router solicitation, length 16
15:45:56.572739 IP 10.0.0.2.32796 > 10.0.0.1.5001: Flags [S], seq 154698910, win 42340, options [mss 1460,sackOK,TS val 2203867783 ecr 0,nop,wscale 9], length 0
15:45:56.599970 IP 10.0.0.2.32796 > 10.0.0.1.5001: Flags [.], ack 2169569234, win 83, options [nop,nop,TS val 2203867805 ecr 3229424418], length 0
15:45:56.600811 IP 10.0.0.2.32796 > 10.0.0.1.5001: Flags [.], seq 0:1448, ack 1, win 83, options [nop,nop,TS val 2203867807 ecr 3229424418], length 1448
15:45:56.602843 IP 10.0.0.2.32796 > 10.0.0.1.5001: Flags [P.], seq 1448:2896, ack 1, win 83, options [nop,nop,TS val 2203867807 ecr 3229424418], length 1448
15:45:56.603308 IP 10.0.0.2.32796 > 10.0.0.1.5001: Flags [.], seq 2896:4344, ack 1, win 83, options [nop,nop,TS val 2203867807 ecr 3229424418], length 1448
15:45:56.603761 IP 10.0.0.2.32796 > 10.0.0.1.5001: Flags [P.], seq 4344:5792, ack 1, win 83, options [nop,nop,TS val 2203867807 ecr 3229424418], length 1448
15:45:56.604096 IP 10.0.0.2.32796 > 10.0.0.1.5001: Flags [.], seq 5792:7240, ack 1, win 83, options [nop,nop,TS val 2203867807 ecr 3229424418], length 1448
15:45:56.604427 IP 10.0.0.2.32796 > 10.0.0.1.5001: Flags [P.], seq 7240:8688, ack 1, win 83, options [nop,nop,TS val 2203867807 ecr 3229424418], length 1448
15:45:56.604730 IP 10.0.0.2.32796 > 10.0.0.1.5001: Flags [.], seq 8688:10136, ack 1, win 83, options [nop,nop,TS val 2203867807 ecr 3229424418], length 1448
15:45:56.605042 IP 10.0.0.2.32796 > 10.0.0.1.5001: Flags [P.], seq 10136:11584, ack 1, win 83, options [nop,nop,TS val 2203867807 ecr 3229424418], length 1448

12 packets captured
12 packets received by filter
0 packets dropped by kernel
mininet> 
```
Above steps first run `iperf` in the server mode at h1 (in the internal network), run `tcpdump` at h3
to see the packets coming from the switch and run `iperf` as the client (initiates the TCP connection) at h2 (in the external network).
At h3, the mirrored packets appear when `tcpdump` is killed by `pkill tcpdump`.

### Marking Criteria

1. [l4mirror.py](./l4mirror.py) can match the SYN packet sent from host 2 to host 1, which must pass the following test (**4%**):
```
python3.8 -m pytest tests/test_l4mirror.py::test_l4mirror1
```
2. [l4mirror.py](./l4mirror.py) meets the all the requirements described in the **Specification** paragraph above, which must pass the following test (**6%**):
```
python3.8 -m pytest tests/test_l4mirror.py
```
Note that since meeting the first criteria is an intermediate step to meet the second criteria, the possible score is 0%, 4% or 10%.

### Hints

The first task will be defining actions (`acts` in [l4mirror.py](./l4mirror.py))
so that the controller at least runs, which is to pass all the traffic between switch port 1 and 2.  You can refer to [l2learn.py](./l2learn.py) for this. The next task will be to identify a TCP packet. If the packet in `_packet_in_handler()` is a TCP packet, the `iph` and `tcph` objects will contain the IP and TCP headers referred as `iph[0]` and `tcph[0]`, respectively.
See
[here](https://ryu.readthedocs.io/en/latest/library_packet_ref/packet_ipv4.html) and [here](https://ryu.readthedocs.io/en/latest/library_packet_ref/packet_tcp.html) for details of IPv4 and TCP objects, respectively.

If the packet comes from port 2 and contains the TCP SYN flag and does not
contain the ACK flag (i.e., active TCP connection from the external network), you would add the
key, which consists of a tuple of `(<src_ip><dst_ip><src_port><dst_port>)`, 
to the dictionary (hash table) `self.ht` with the value 1 (indicate packet count).
Then also add a new action, which sends the packet to port 3 (**in addition to** the action that sends to port 1), to the actions list (`acts`).
However, since the controller wants to keep seeing the packets that belong to this TCP connection and arrive at switch port 2, it does not add the flow to the switch yet; every such a packet will increment the packet counter in the dictionary, and when seeing the 10th packet, the controller will remove the flow key in the dictionary and adds the flow entry to the switch (see [l2learn.py](./l2learn.py) for syntax, but you also have to specify `eth_type`, `ipv4_src`, `ipv4_dst`, `ip_proto`, `tcp_src` and `tcp_dst` optional arguments for this task), as it does not need to mirror the packets to switch port 3 anymore.
Flows for TCP packets arriving at port 1 must be added to the switch
unconditionally.

The sample solution (not provided) consists of 76 lines, but this number is just
a reference, and no need to match.
