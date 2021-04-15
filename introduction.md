# Quick OpenFlow and Mininet Tutorial

OpenFlow is a dominant protocol that makes up a Software Defined Network
(SDN), which offers more flexible packet processing within the network than the
traditional L2/L3 networks.
It separates controllers from switches; at the beginning packets arriving at an OpenFlow switch 
are diverted to the OpenFlow controller, that runs either locally or remotely.
The controller decides *action*, which literally means what to do for the packet, based on the packet headers and
other metadata, such as input switch port.
For example, the controller may simply drop the packet or return the packet to
the switch to forward the packet to another switch port.
More importantly, the controller can also insert a *flow* in the switch so that the
subsequent packets that match the same flow do not travel to the controller.
A flow can be defined by various meaningful forms.  For example, a flow may match the packets with a specific arrival switch port and destination MAC address; another flow may match the packets with an specific switch port, IPv4 and TCP header and specific four-tuple of `<src_ip><dst_ip><src_port><dst_port>`.


### Mininet network emulator and Ryu OpenFlow controller.

[Mininet](http://mininet.org/) is a network emulator that include both the
networks and hosts, and runs in a Linux VM or
physical machine.
As we will do in the assignments, we can attach an OpenFlow controller written
with [Ryu](https://ryu-sdn.org/) framework.  Let's try out Mininet and Ryu in
the rest of this introduction.

Our [VM](../vm/README.md) preinstalls both Mininet and Ryu.
To instantiate a controller with the L2 learning switch feature, run:
```
vagrant@ubuntu-focal:~$ ryu-manager l2learn.py 
loading app l2learn.py
loading app ryu.controller.ofp_handler
instantiating app l2learn.py of L2Learn14
instantiating app ryu.controller.ofp_handler of OFPHandler
```
In another window, create a Mininet network that consists of a switch between three hosts.
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
mininet> 
```
The three hosts are named as h1, h2 and h3, and the switch is named as s1.
You can also see similar information using following commands, which also
contains the controller c0:
```
mininet> nodes
available nodes are: 
c0 h1 h2 h3 s1
mininet> net
h1 h1-eth0:s1-eth1
h2 h2-eth0:s1-eth2
h3 h3-eth0:s1-eth3
s1 lo:  s1-eth1:h1-eth0 s1-eth2:h2-eth0 s1-eth3:h3-eth0
c0
mininet> dump
<Host h1: h1-eth0:10.0.0.1 pid=41964> 
<Host h2: h2-eth0:10.0.0.2 pid=41968> 
<Host h3: h3-eth0:10.0.0.3 pid=41970> 
<OVSSwitch s1: lo:127.0.0.1,s1-eth1:None,s1-eth2:None,s1-eth3:None pid=41975> 
<RemoteController c0: 127.0.0.1:6653 pid=41957> 
mininet>
```
You can execute a UNIX command in any host, like:
```
mininet> h2 ping -c 1 h1
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.175 ms

--- 10.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.175/0.175/0.175/0.000 ms
```
There are some commands to be executed without specifying the host:
```
mininet> pingall
*** Ping: testing ping reachability
h1 -> h2 h3 
h2 -> h1 h3 
h3 -> h1 h2 
*** Results: 0% dropped (6/6 received)
```
pingall generates pings between all the hosts.

Now let's see the controler behavior.
Stop the ryu-manager (ctrl+c) and exit from the mininet prompt (type "exit")
Edit [l2learn.py](./l2learn.py) to insert a `print(in_port, pkt)` line right after the line of `in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))` in `_packet_in_handler()` method, which is invoked every time the controller receives a packet.
Then run `ryu-manager l2learn.py` again and in another window, start mininet as before (`sudo mn --topo single,3 --mac --controller remote`).
You might already see a lot of packets.
When you run `pingall` in the mininet prompt, you will see the packets received at the controller in the ryu-manager output.

Next, let's understand what the controler implementation looks like.
Going back to [l2learn.py](./l2learn.py), again take a look at `_packet_in_handler()`:
```
      @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
      def _packet_in_handler(self, ev):
 1        msg = ev.msg
 2        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
 3        dp = msg.datapath
 4        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
 5        eth = pkt.get_protocols(ethernet.ethernet)[0]
 6        dst, src = (eth.dst, eth.src)
 7        self.ht.setdefault(did, {})
 8        he = self.ht[did] # shorthand
 9        he[src] = in_port
10        out_port = he[dst] if dst in he else ofp.OFPP_FLOOD
11        acts = [psr.OFPActionOutput(out_port)]
12        if out_port != ofp.OFPP_FLOOD:
13            mtc = psr.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
14            self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
15            if msg.buffer_id != ofp.OFP_NO_BUFFER:
16                return
17        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
18        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
19                               in_port=in_port, actions=acts, data=data)
20        dp.send_msg(out)
```
This code maintains per-datapath hash tables, although only one datapath exists
in our network (line 7-8). 
This code creates a hash table entry whose key is a source MAC address (`src`) and value is an
input port (`in_port`) (line 9) so that we can determine the output switch port of the future packets that have this MAC address as
the *destination*; you will understand this more in the next lines.
The controller then determines the output port based on whether the hash table entry for the
destination MAC address (`dst`) exists or not (line 10); since this is a L2
learning switch, the packet is *flooded* to all the ports except for the input
port if the destination port cannot be identified (i.e., has not been learned).
The controller then generates the actions list applied to this packet (line 11).
If the packet destination has been identified (line 12), the code inserts the
*flow* to the switch, which matches the same input port and source and destination MAC
address as this packet, because we already learned the output port for the MAC
address indicated by the source MAC address of this packet, and thus the packets that match
this flow do not have to come to the controller anymore (line 13-14).
In general, it is important to minimize the controller involvement in SDN
to maximize performance.
Finally, the code applies the packet action (line 18-20).



That's it, let's move on to the assignments in [README.md](./README.md).
If you want to learn more about Mininet, [Mininet Walkthrough](http://mininet.org/walkthrough/) is really useful.
To learn Ryu, [Ryu Controller Tutorial](http://sdnhub.org/tutorials/ryu/) is
useful.

SDN is an active research area. You can find interesting research in this area at [NSDI](https://www.usenix.org/conference/nsdi20), [SIGCOMM](http://sigcomm.org/events/sigcomm-conference) and [SOSR](http://www.sigcomm.org/events/sosr).
