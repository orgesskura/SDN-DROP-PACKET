import pytest
from l2learn import L2Learn14
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_4, ofproto_v1_4_parser, ether
from ryu.ofproto.ofproto_v1_4_parser import OFPPacketIn, OFPMatch
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.udp import udp
from ryu.lib.packet.in_proto import IPPROTO_UDP
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

def genpktin(smac, dmac, sip, dip, dp, pi):
    eh = ethernet(dmac, smac, ether.ETH_TYPE_IP)
    iph = ipv4(total_length=64, proto=IPPROTO_UDP, src=sip, dst=dip)
    udph = udp(src_port=20000, dst_port=20001)
    p = Packet()
    for h in (eh, iph, udph):
        p.add_protocol(h)
    p.serialize()
    packetIn = OFPPacketIn(dp, match=OFPMatch(in_port=pi), data=p.data)
    return packetIn

def test_l2learn():
    nnodes = 3
    macs, ips = (genmacs(nnodes*2), genips(nnodes*2))
    ctlr = L2Learn14()
    dp = _Datapath()

    for i in range(nnodes):
        si, di, pi = (i*2, i*2+1, i)
        pin = genpktin(macs[si], macs[di], str(ips[si]), str(ips[di]), dp, pi)
        ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(pin))
        assert dp.out.actions[0].port == dp.ofproto.OFPP_FLOOD

        # check if we learned
        si, di, pi = (i*2+1, i*2, 2-i)
        pin = genpktin(macs[si], macs[di], str(ips[si]), str(ips[di]), dp, pi)
        ctlr._packet_in_handler(ofp_event.EventOFPPacketIn(pin))
        assert dp.out.instructions[0].actions[0].port == i
