from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp


class Config:
    controller_macAddr = '7e:49:b3:f0:f9:99'  # don't modify, a dummy mac address for fill the mac enrty
    controller_ip = '192.168.1.1'
    dns = '8.8.8.8'  # don't modify, just for the dns entry
    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.200'  # can be modified
    netmask = '255.255.255.0'  # can be modified

    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer:
    hardware_addr = Config.controller_macAddr

    controller_ip = Config.controller_ip
    controller_ip_list = controller_ip.split('.')
    controller_ip_bytes = b''
    for i in controller_ip_list:
        controller_ip_bytes = controller_ip_bytes + int(i).to_bytes(1, 'big')

    dns = Config.dns
    dns_list = dns.split('.')
    dns_bytes = b''
    for i in dns_list:
        dns_bytes = dns_bytes + int(i).to_bytes(1, 'big')

    netmask = Config.netmask
    netmask_list = netmask.split('.')
    netmask_bytes = b''
    for i in netmask_list:
        netmask_bytes = netmask_bytes + int(i).to_bytes(1, 'big')

    start_ip = Config.start_ip
    end_ip = Config.end_ip

    pool = []

    netmask_decimal = 0
    for i in netmask_list:
        netmask_decimal <<= 8
        netmask_decimal += int(i)
    start_ip_list = start_ip.split('.')
    start_ip_decimal = 0
    for i in start_ip_list:
        start_ip_decimal <<= 8
        start_ip_decimal += int(i)
    subnet_id_decimal = netmask_decimal & start_ip_decimal
    netmask_reverse_decimal = netmask_decimal ^ 4294967295
    start_ip_postfix_decimal = start_ip_decimal & netmask_reverse_decimal

    end_ip_list = end_ip.split('.')
    end_ip_decimal = 0
    for i in end_ip_list:
        end_ip_decimal <<= 8
        end_ip_decimal += int(i)
    end_ip_postfix_decimal = end_ip_decimal & netmask_reverse_decimal
    for i in range(start_ip_postfix_decimal, (end_ip_postfix_decimal + 1)):
        pool.append(i)

    current_pkt_flags = 0
    request_ip_bytes = b''

    @classmethod
    def offer_ip(cls):
        addr_str = None
        if len(cls.pool) > 0:
            addr_postfix_decimal = cls.pool.pop(0)
            addr = cls.subnet_id_decimal + addr_postfix_decimal
            addr_str = ''
            addr_str = addr_str + str((addr >> 24) & 255) + '.'
            addr_str = addr_str + str((addr >> 16) & 255) + '.'
            addr_str = addr_str + str((addr >> 8) & 255) + '.'
            addr_str = addr_str + str(addr & 255)
        else:
            addr_str = '0.0.0.0'
        return addr_str

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        # TODO: Generate DHCP ACK packet here
        request_ip = str(cls.request_ip_bytes[0]) + '.' + str(cls.request_ip_bytes[1]) + '.' + str(cls.request_ip_bytes[2]) + '.' + str(cls.request_ip_bytes[3])
        ipv4_dst_ip = None
        if cls.current_pkt_flags == 0:
            ipv4_dst_ip = request_ip
        else:
            ipv4_dst_ip = '255.255.255.255'
        p = packet.Packet()
        e = ethernet.ethernet(dst=pkt.get_protocol(ethernet.ethernet).src,
                              src=cls.hardware_addr,
                              ethertype=2048)
        v = ipv4.ipv4(dst=ipv4_dst_ip, option=None,
                      proto=17, src=cls.controller_ip)
        u = udp.udp(dst_port=68, src_port=67)
        d = dhcp.dhcp(chaddr=pkt.get_protocol(dhcp.dhcp).chaddr,
                      hlen=6, htype=pkt.get_protocol(dhcp.dhcp).htype, op=2,
                      xid=pkt.get_protocol(dhcp.dhcp).xid,
                      yiaddr=request_ip, boot_file='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', sname='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                      options=dhcp.options(magic_cookie='99.130.83.99', option_list=[dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=b'\x05'), dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT, value=cls.netmask_bytes), dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT, value=cls.controller_ip_bytes), dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT, value=cls.dns_bytes), dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, value=b'\x00\x03\xf4\x80')]))
        p.add_protocol(e)
        p.add_protocol(v)
        p.add_protocol(u)
        p.add_protocol(d)
        return p

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        offer_ip = cls.offer_ip()
        ipv4_dst_ip = None
        if cls.current_pkt_flags == 0:
            ipv4_dst_ip = offer_ip
        else:
            ipv4_dst_ip = '255.255.255.255'
        p = packet.Packet()
        e = ethernet.ethernet(dst=pkt.get_protocol(ethernet.ethernet).src,
                              src=cls.hardware_addr,
                              ethertype=2048)
        v = ipv4.ipv4(dst=ipv4_dst_ip, option=None,
                      proto=17, src=cls.controller_ip)
        u = udp.udp(dst_port=68, src_port=67)
        d = dhcp.dhcp(chaddr=pkt.get_protocol(dhcp.dhcp).chaddr,
                      hlen=6, htype=pkt.get_protocol(dhcp.dhcp).htype, op=2,
                      xid=pkt.get_protocol(dhcp.dhcp).xid,
                      yiaddr=offer_ip, boot_file='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', sname='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                      options=dhcp.options(magic_cookie='99.130.83.99', option_list=[dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=b'\x02'), dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT, value=cls.netmask_bytes), dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT, value=cls.controller_ip_bytes), dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT, value=cls.dns_bytes), dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, value=b'\x00\x03\xf4\x80')]))
        p.add_protocol(e)
        p.add_protocol(v)
        p.add_protocol(u)
        p.add_protocol(d)
        return p
        # TODO: Generate DHCP OFFER packet here

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        decoded_packet = pkt.get_protocol(dhcp.dhcp)
        cls.current_pkt_flags = decoded_packet.flags
        pkt_options_list = decoded_packet.options.option_list
        pkt_dhcp_type = b''
        for i in pkt_options_list:
            if i.tag == 53:
                pkt_dhcp_type = i.value
            elif i.tag == 50:
                cls.request_ip_bytes = i.value
        reply = None
        if pkt_dhcp_type == b'\x01':
            reply = cls.assemble_offer(pkt, datapath)
        elif pkt_dhcp_type == b'\x03':
            reply = cls.assemble_ack(pkt, datapath, port)
        if (pkt_dhcp_type == b'\x01') or (pkt_dhcp_type == b'\x03'):
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
