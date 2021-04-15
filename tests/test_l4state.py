import pytest
from l4state import L4State14
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_4, ofproto_v1_4_parser, ether
from ryu.ofproto.ofproto_v1_4_parser import OFPPacketIn, OFPMatch
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.tcp import tcp
from ryu.lib.packet.udp import udp
from ryu.lib.packet.in_proto import IPPROTO_TCP
import random
from ipaddress import ip_address

class _Datapath(object):
    ofproto = ofproto_v1_4
    ofproto_parser = ofproto_v1_4_parser
    def __init__(self):
        self.id = 1
    def send_msg(self, msg):
        self.out = msg

def genmacs(n):
    r = []
    for i in range(n):
        base = '02:30'
        for _ in range(4):
            base += ':{:02x}'.format(random.randrange(0, 0xff))
        r.append(base)
    return tuple(r)

def genips(n):
    r = []
    for i in range(n):
        base = ip_address('192.168.1.2')
        r.append(ip_address(int(base)+i))
    return tuple(r)

def genports(n):
    return tuple(random.sample([i for i in range(20000, 0xffff)], n))

def genpktin(smac, dmac, sip, dip, sport, dport, dp, pi, usetcp=True):
    eh = ethernet(dmac, smac, ether.ETH_TYPE_IP)
    iph = ipv4(total_length=64, proto=IPPROTO_TCP, src=sip, dst=dip)
    tcph = tcp(src_port=sport, dst_port=dport) if usetcp else udp(
            src_port=sport, dst_port=dport)
    p = Packet()
    for h in (eh, iph, tcph):
        p.add_protocol(h)
    p.serialize()
    packetIn = OFPPacketIn(dp, match=OFPMatch(in_port=pi), data=p.data)
    return packetIn

def test_l4state1():
    nnodes = 2
    macs, ips, ports = (genmacs(nnodes*2), genips(nnodes*2), genports(nnodes*2))
    ctlr = L4State14()
    dp = _Datapath()

    n2n1 = genpktin(macs[0], macs[1], ips[0], ips[1], ports[0], ports[1], dp, 2)
    n2n1_2 = genpktin(macs[0], macs[1], ips[0], ips[1], ports[0], ports[1], dp,
            2, usetcp=False)
    n1n2 = genpktin(macs[1], macs[0], ips[1], ips[0], ports[1], ports[0], dp, 1)

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1))
    assert dp.out.actions[0].port != 1 and not hasattr(dp.out, 'instructions')

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1_2))
    assert dp.out.actions[0].port == 1

def test_l4state2():
    nnodes = 2
    macs, ips, ports = (genmacs(nnodes*2), genips(nnodes*2), genports(nnodes*2))
    ctlr = L4State14()
    dp = _Datapath()

    n2n1 = genpktin(macs[0], macs[1], ips[0], ips[1], ports[0], ports[1], dp, 2)
    n1n2 = genpktin(macs[1], macs[0], ips[1], ips[0], ports[1], ports[0], dp, 1)

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n1n2))
    m = dp.out.match
    f = (m['in_port'], m['ipv4_src'], m['ipv4_dst'], m['tcp_src'], m['tcp_dst'])
    o = dp.out.instructions[0].actions[0].port
    assert f == (1, str(ips[1]), str(ips[0]), ports[1], ports[0]) and o == 2

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1))
    m = dp.out.match
    f = (m['in_port'], m['ipv4_src'], m['ipv4_dst'], m['tcp_src'], m['tcp_dst'])
    o = dp.out.instructions[0].actions[0].port
    assert f == (2, str(ips[0]), str(ips[1]), ports[0], ports[1]) and o == 1
