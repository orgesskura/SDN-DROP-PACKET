import pytest
from l4mirror import L4Mirror14
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_4, ofproto_v1_4_parser, ether
from ryu.ofproto.ofproto_v1_4_parser import OFPPacketIn, OFPMatch
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.tcp import tcp
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

def genpktin(smac, dmac, sip, dip, sport, dport, dp, pi, syn=False):
    eh = ethernet(dmac, smac, ether.ETH_TYPE_IP)
    iph = ipv4(total_length=64, proto=IPPROTO_TCP, src=sip, dst=dip)
    bits = 0 if not syn else 0x02
    tcph = tcp(src_port=sport, dst_port=dport, bits=bits)
    p = Packet()
    for h in (eh, iph, tcph):
        p.add_protocol(h)
    p.serialize()
    packetIn = OFPPacketIn(dp, match=OFPMatch(in_port=pi), data=p.data)
    return packetIn

def test_l4mirror1():
    nnodes = 2
    macs, ips, ports = (genmacs(nnodes*2), genips(nnodes*2), genports(nnodes*2))
    ctlr = L4Mirror14()
    dp = _Datapath()

    n2n1 = genpktin(macs[0], macs[1], ips[0], ips[1], ports[0], ports[1], dp, 2, syn=True)
    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1))
    for p in (1, 3):
        for a in dp.out.actions:
            if a.port == p:
                break
        else:
            assert False
    assert (str(ips[0]), str(ips[1]), ports[0], ports[1]) in ctlr.ht

    n2n1 = genpktin(macs[0], macs[1], ips[0], ips[1], ports[0], ports[1], dp, 2)
    for i in range(8):
        ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1))
        for p in (1, 3):
            for a in dp.out.actions:
                if a.port == p:
                    break
            else:
                assert False
        assert ctlr.ht[(str(ips[0]), str(ips[1]), ports[0], ports[1])] == i+2

    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1))
    assert not (str(ips[0]), str(ips[1]), ports[0], ports[1]) in ctlr.ht

def test_l4mirror2():
    nnodes = 2
    macs, ips, ports = (genmacs(nnodes*2), genips(nnodes*2), genports(nnodes*2))
    ctlr = L4Mirror14()
    dp = _Datapath()

    n2n1 = genpktin(macs[0], macs[1], ips[0], ips[1], ports[0], ports[1], dp, 2, syn=True)
    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1))
    n2n1 = genpktin(macs[0], macs[1], ips[0], ips[1], ports[0], ports[1], dp, 2)
    for i in range(9):
        ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1))
    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n2n1))
    assert dp.out.instructions[0].actions[0].port == 1
    assert dp.out.match['in_port'] == 2
    assert dp.out.match['ipv4_src'] == str(ips[0])
    assert dp.out.match['ipv4_dst'] == str(ips[1])
    assert dp.out.match['tcp_src'] == ports[0]
    assert dp.out.match['tcp_dst'] == ports[1]

    n1n2 = genpktin(macs[1], macs[0], ips[1], ips[0], ports[1], ports[0], dp, 1)
    ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(n1n2))
    assert dp.out.instructions[0].actions[0].port == 2
    assert dp.out.match['in_port'] == 1
    assert dp.out.match['ipv4_src'] == str(ips[1])
    assert dp.out.match['ipv4_dst'] == str(ips[0])
    assert dp.out.match['tcp_src'] == ports[1]
    assert dp.out.match['tcp_dst'] == ports[0]
