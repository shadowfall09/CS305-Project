import heapq

from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp


class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99'  # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8'  # don't modify, just for the dns entry
    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.200'  # can be modified
    netmask = '255.255.255.0'  # can be modified

    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    ip_pool_start = int(start_ip.split('.')[-1])
    ip_pool_end = int(start_ip.split('.')[-1])
    pool = []
    for i in range(ip_pool_start, ip_pool_end + 1):
        heapq.heappush(pool, i)

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        # TODO: Generate DHCP ACK packet here
        return None

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        p = packet.Packet()
        e = ethernet.ethernet(dst=pkt.get_protocol(ethernet.ethernet).src,
                              src=cls.hardware_addr,
                              ethertype=2048)
        v = ipv4.ipv4(dst='255.255.255.255', flags=0, header_length=5, identification=0, offset=0, option=None,
                      proto=17, src='192.168.1.1', tos=16, ttl=128, version=4)
        # d = dhcp.dhcp(chaddr=pkt.get_protocol(dhcp.dhcp).chaddr, ciaddr='0.0.0.0', flags=0, giaddr='0.0.0.0',
        #               hlen=6, hops=0, htype=pkt.get_protocol(dhcp.dhcp).htype, op=2, secs=0,
        #               siaddr='0.0.0.0', xid=pkt.get_protocol(dhcp.dhcp).xid,
        #               yiaddr='192.168.1.1')
        # d = dhcp.dhcp(chaddr='00:00:00:00:00:01',
        #               op=2)
        u = udp.udp(dst_port=68, src_port=67)
        p.add_protocol(e)
        p.add_protocol(v)
        # p.add_protocol(d)
        p.add_protocol(u)
        # p.serialize()
        return p
        # TODO: Generate DHCP OFFER packet here

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        decoded_packet = pkt.get_protocol(dhcp.dhcp)
        if str(decoded_packet.yiaddr) == '0.0.0.0':
            reply = cls.assemble_offer(pkt, datapath)
        else:
            reply = cls.assemble_ack(pkt, datapath, port)
        cls._send_packet(datapath, port, reply)
        # TODO: Specify the type of received DHCP packet
        # You may choose a valid IP from IP pool and genereate DHCP OFFER packet
        # Or generate a DHCP ACK packet
        # Finally send the generated packet to the host by using _send_packet method

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
