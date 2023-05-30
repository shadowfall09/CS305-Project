import matplotlib.pyplot as plt
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import event, switches
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_0
from dhcp import DHCPServer
from queue import PriorityQueue
import networkx as nx

switches_list = []
link_between_switch = []
hosts = []
figure_cnt = 0


class Graph:
    def __init__(self, num_of_vertices):
        self.vertices = num_of_vertices
        self.edges = [[-1 for i in range(num_of_vertices)] for j in range(num_of_vertices)]
        self.visited = []

    def add_edge(self, u, v):
        self.edges[u][v] = 1

    def dijkstra(self, start_vertex):
        self.visited = []
        D = {v: float('inf') for v in range(self.vertices)}
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


class ControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        print("switch_add")
        switches_list.append(ev.switch)
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)
        """
        Event handler indicating a switch has come online.
        """

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        print('switch_delete')
        for switch in switches_list:
            if switch.dp.id == ev.switch.dp.id:
                switches_list.remove(switch)
                break
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)
        """
        Event handler indicating a switch has been removed
        """

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        print('host_add')
        hosts.append(ev.host)
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        print('link_add')
        link_between_switch.append(ev.link)
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)
        """
        Event handler indicating a link between two switches has been added
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        print('link delete')
        for link in link_between_switch:
            if (link.src.dpid == ev.link.src.dpid) and (link.src.port_no == ev.link.src.port_no) and (link.dst.dpid == ev.link.dst.dpid) and (link.dst.port_no == ev.link.dst.port_no):
                link_between_switch.remove(link)
        graph = self.Dijkstra_change()
        self.generate_flow_table(graph)
        """
        Event handler indicating when a link between two switches has been deleted
        """
        # TODO:  Update network topology and flow rules

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
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        # TODO:  Update network topology and flow rules

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
