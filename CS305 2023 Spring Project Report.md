# CS305 2023 Spring Project Report

**秦尧 12112016**

**陶毅诚 12112003**

**谢尚儒 12112017**



## Environment setup

We set our environment on Ubuntu 22.04.2 desktop, as it's better to start multiple terminals to test functions.

![image-20230530112727179](D:\SUSTech\CS305\CS305-Project\image-20230530112727179.png)



## DHCP

We implement our simple DHCP server in `dhcp.py`.

For configurations like **IP**, **DNS**, **netmask**, we all turn into its corresponding binary form, so that it's compatible for sending.

```python
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
```

As we need to send `OFFER` and `ACK` packets to respond, we complete the function `assemble_ack` and `assemble_offer` and generate corresponding packets.

```python
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
```
Both of these two methods will be executed when acceptted corresponding dhcp packets. When executing, a method would offer an available ip address.
```python
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
```



## Shortest path switching

All codes relative to this part are completed in `controller.py`. The basic parts of code has been correctly implemented as shown below:
```python
    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        print("switch_add")
        switches_list.append(ev.switch)
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        print('switch_delete')
        for switch in switches_list:
            if switch.dp.id == ev.switch.dp.id:
                switches_list.remove(switch)
                break
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)
        

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        print('host_add')
        hosts.append(ev.host)
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)
      

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        print('link_add')
        link_between_switch.append(ev.link)
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)
       

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        print('link delete')
        for link in link_between_switch:
            if (link.src.dpid == ev.link.src.dpid) and (link.src.port_no == ev.link.src.port_no) and (link.dst.dpid == ev.link.dst.dpid) and (link.dst.port_no == ev.link.dst.port_no):
                link_between_switch.remove(link)
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)
       

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        print('port modify')
        for switch in switches_list:
            if switch.dp.id == ev.port.dpid:
                for i in range(len(switch.ports)):
                    if switch.ports[i].port_no == ev.port.port_no:
                        switch.ports[i] = ev.port
        for link in link_between_switch:
            if (link.src.dpid == ev.port.dpid) and (link.src.port_no == ev.port.port_no):
                link.src = ev.port
            if (link.dst.dpid == ev.port.dpid) and (link.dst.port_no == ev.port.port_no):
                link.dst = ev.port
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    
    
    def packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            pkt = packet.Packet(data=msg.data)
            pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
            inPort = msg.in_port
            if not pkt_dhcp:
                if pkt.get_protocols(arp.arp):
                    if pkt.get_protocol(arp.arp).dst_ip != pkt.get_protocol(arp.arp).src_ip:
                        reply_pkt = packet.Packet()
                        reply_mac = '00:00:00:00:00:00'
                        for host in hosts:
                            if host.ipv4[0] == pkt.get_protocol(arp.arp).dst_ip:
                                reply_mac = host.mac
                                break
                        e = ethernet.ethernet(dst=pkt.get_protocol(ethernet.ethernet).src,
                                              src=DHCPServer.hardware_addr,
                                              ethertype=pkt.get_protocol(ethernet.ethernet).ethertype)
                        a = arp.arp(dst_ip=pkt.get_protocol(arp.arp).src_ip, dst_mac=pkt.get_protocol(arp.arp).src_mac,
                                    opcode=arp.ARP_REPLY,
                                    src_ip=pkt.get_protocol(arp.arp).dst_ip, src_mac=reply_mac)
                        reply_pkt.add_protocol(e)
                        reply_pkt.add_protocol(a)
                        self._send_packet(datapath, inPort, reply_pkt)
                # TODO: handle other protocols like ARP
                pass
            else:
                DHCPServer.handle_dhcp(datapath, inPort, pkt)
            return
        except Exception as e:
            self.logger.error(e)        
       
```
Our group choose to take dijkstra algorithm to implement to the shortest path switching. So that we created a special class called `Graph` to help us record the total information about the topology model. In the class, we achieve basic dijkstra algorithm through method `dijkstra(self, start_vertex)` and return the distance and previous vertices.

```python
class Graph:
    def __init__(self, num_of_vertices):
        self.vertices = num_of_vertices
        self.edges = [[-1 for i in range(num_of_vertices)] for j in range(num_of_vertices)]
        self.visited = []

    def add_edge(self, u, v):
        self.edges[u][v] = 1

    def dijkstra(self, start_vertex):
        self.visited = []
        D = {}
        for v in range(self.vertices):
            D[v] = float('inf')
        D[start_vertex] = 0
        pq = PriorityQueue()
        pq.put((0, start_vertex))
        previousVertex = {}

        while not pq.empty():
            (dist, current_vertex) = pq.get()
            self.visited.append(current_vertex)

            for neighbor in range(self.vertices):
                if self.edges[current_vertex][neighbor] != -1:
                    distance = self.edges[current_vertex][neighbor]
                    if neighbor not in self.visited:
                        old_cost = D[neighbor]
                        new_cost = D[current_vertex] + distance
                        if new_cost < old_cost:
                            pq.put((new_cost, neighbor))
                            D[neighbor] = new_cost
                            previousVertex[neighbor] = current_vertex
        return D, previousVertex
```

Then we implemented a method `Dijkstra_change(self)` to change the graph and display the functional result by print it out when operating the process. It also create the plot shown by matplotLib and generate graph 'G' then save it.

```python
    def Dijkstra_change(self):
        dic = {}
        dic2 = {}
        o = 0
        G = nx.Graph()
        for one_switch in switches_list:
            dic[o] = one_switch.dp.id
            dic2[one_switch.dp.id] = o
            o += 1
            G.add_node(one_switch.dp.id)
        graph = Graph(len(switches_list))
        for link in link_between_switch:
            if (link.src.dpid in dic2) and (link.dst.dpid in dic2):
                if (link.src._state == 0) and (link.dst._state == 0):
                    G.add_edge(link.src.dpid, link.dst.dpid)
                    graph.add_edge(dic2[link.src.dpid], dic2[link.dst.dpid])
        nx.draw(G,with_labels=True)
        global figure_cnt
        plt.savefig(f"/home/rt/CS305-Project/network_fig/fig{figure_cnt}.jpg")
        figure_cnt += 1
        plt.close()
        for source0 in range(len(switches_list)):
            D, previousVertex = graph.dijkstra(source0)
            for target0 in range(len(switches_list)):
                try:
                    path = []
                    cheapest_path = []
                    target = target0
                    while True:
                        if target == source0:
                            path.append(source0)
                            break
                        else:
                            path.append(target)
                            target = previousVertex[target]
                    for point in path[:: -1]:
                        cheapest_path.append(str(dic[point]))
                    cheapest_path = "->".join(cheapest_path)
                    print(f"distance from switch {dic[source0]} to switch {dic[target0]} is {D[target0]},"
                          f"the shortest path is {cheapest_path}")
                except KeyError:
                    print(f"switch {dic[source0]} is not connected to switch {dic[target0]}")
        return graph
```

Also, we insert the generated graph into the flow table of each switch and alter the attibutes of switches.
```python
    def insert_flow_table(self, datapath, dst_mac, port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(dl_dst=dst_mac)
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPFlowMod(datapath=datapath, match=match, command=ofproto.OFPFC_ADD, actions=actions)
        datapath.send_msg(out)

    def generate_flow_table(self, graph):
        for i in range(0, len(hosts)):
            for j in range(i + 1, len(hosts)):
                switch1_index = -1
                switch2_index = -1
                dpid1 = hosts[i].port.dpid
                dpid2 = hosts[j].port.dpid
                for k in range(0, len(switches_list)):
                    if switches_list[k].dp.id == dpid1:
                        switch1_index = k
                    if switches_list[k].dp.id == dpid2:
                        switch2_index = k
                    if (switch1_index != -1) and (switch2_index != -1):
                        break
                self.insert_flow_table(switches_list[switch1_index].dp, hosts[i].mac, hosts[i].port.port_no)
                self.insert_flow_table(switches_list[switch2_index].dp, hosts[j].mac, hosts[j].port.port_no)
                (distances, parents) = graph.dijkstra(switch1_index)
                if distances[switch2_index] != float('inf'):
                    if switch2_index not in parents:
                        continue
                    switch_index_current = parents[switch2_index]
                    switch_index_last = switch2_index
                    while True:
                        for link in link_between_switch:
                            if (link.src.dpid == switches_list[switch_index_current].dp.id) and (link.dst.dpid == switches_list[switch_index_last].dp.id):
                                self.insert_flow_table(switches_list[switch_index_current].dp, hosts[j].mac, link.src.port_no)
                                self.insert_flow_table(switches_list[switch_index_last].dp, hosts[i].mac, link.dst.port_no)
                                break
                        if switch_index_current in parents:
                            switch_index_last = switch_index_current
                            switch_index_current = parents[switch_index_current]
                        else:
                            break
```
## Bonus

- Implement the function of DHCP lease duration when offer and ack.
```python
d = dhcp.dhcp(options=dhcp.options(magic_cookie='99.130.83.99', option_list=[dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=b'\x05'), dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT, value=cls.netmask_bytes), dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT, value=cls.controller_ip_bytes), dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT, value=cls.dns_bytes), dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, value=b'\x00\x03\xf4\x80')]))#here implement lease_time 
                
```



## Testing results



### Switching tests


#### test_network.py

![switch11](D:\SUSTech\CS305\CS305-Project\switch11.jpg)

![switch12](D:\SUSTech\CS305\CS305-Project\switch12.jpg)



#### complex_network.py
It is the complex testcase to prove the robustness of program.

![switch21](D:\SUSTech\CS305\CS305-Project\switch21.jpg)
![Collage_20230531_012242](C:\Users\13938\Desktop\Collage_20230531_012242.jpg)

And here is the completed plot of the topology of the complex testcase, which is drawn by matplotLib.
![figureOfComplex](D:\SUSTech\CS305\CS305-Project\figureOfComplex.jpg)

### dhcp tests
![dhcp1](D:\SUSTech\CS305\CS305-Project\dhcp1.jpg)
![dhcp2](D:\SUSTech\CS305\CS305-Project\dhcp2.jpg)