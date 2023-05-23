from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp


class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99'  # don't modify, a dummy mac address for fill the mac enrty
    controller_ip = '192.168.1.1'
    dns = '8.8.8.8'  # don't modify, just for the dns entry
    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.200'  # can be modified
    netmask = '255.255.255.0'  # can be modified

    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    controller_ip = Config.controller_ip
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    netmask_list = netmask.split('.')
    netmask_bytes = b''
    for i in netmask_list:
        netmask_bytes = netmask_bytes + int(i).to_bytes(1, 'big')
    dns = Config.dns
    ip_pool_start = int(start_ip.split('.')[-1])
    ip_pool_end = int(end_ip.split('.')[-1])
    pool = []
    print(ip_pool_start)
    print(ip_pool_end)
    for i in range(ip_pool_start, ip_pool_end + 1):
        print(i)
        pool.append(i)

    print(pool)

    @classmethod
    def offer_ip(cls):
        addr_last_8 = cls.pool.pop(0)
        print(cls.pool)
        print(addr_last_8)
        return '192.168.1.' + str(addr_last_8)

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
        v = ipv4.ipv4(dst='255.255.255.255', option=None,
                      proto=17, src=cls.controller_ip)
        # v = ipv4.ipv4(dst='255.255.255.255', flags=0, header_length=5, identification=0, offset=0, option=None,
        #               proto=17, src=cls.controller_ip, tos=16, ttl=128, version=4)
        u = udp.udp(dst_port=68, src_port=67)
        d = dhcp.dhcp(chaddr=pkt.get_protocol(dhcp.dhcp).chaddr,
                      hlen=6, htype=pkt.get_protocol(dhcp.dhcp).htype, op=2,
                      xid=pkt.get_protocol(dhcp.dhcp).xid,
                      siaddr=cls.controller_ip,
                      yiaddr=cls.offer_ip(), boot_file='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', sname='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                      options=dhcp.options(magic_cookie='99.130.83.99', option_list=[dhcp.option(tag=53, value=b'\x02'), dhcp.option(tag=1, value=cls.netmask_bytes)]))
        # d = dhcp.dhcp(chaddr=pkt.get_protocol(dhcp.dhcp).chaddr, ciaddr='0.0.0.0', flags=0, giaddr='0.0.0.0',
        #               hlen=6, hops=0, htype=pkt.get_protocol(dhcp.dhcp).htype, op=2, secs=0,
        #               siaddr='0.0.0.0', xid=pkt.get_protocol(dhcp.dhcp).xid,
        #               yiaddr=cls.controller_ip, sname='\0', boot_file='\0')
        # d = dhcp.dhcp(chaddr='00:00:00:00:00:01',
        #               op=2)
        p.add_protocol(e)
        p.add_protocol(v)
        p.add_protocol(u)
        p.add_protocol(d)
        # p.serialize()
        print(p.get_protocol(dhcp.dhcp))
        return p
        # TODO: Generate DHCP OFFER packet here

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        decoded_packet = pkt.get_protocol(dhcp.dhcp)
        print(decoded_packet)
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
