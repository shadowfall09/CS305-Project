from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import event, switches
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp
from dhcp import DHCPServer
from queue import PriorityQueue

switch = []
link_between_switch = []
host = []

class ControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        print("switch_add")
        switch.append(ev.switch.dp)
        print(ev.switch.dp.ports)
        # attributes = vars(ev.switch.dp.ports)
        # print(attributes)
        """
        Event handler indicating a switch has come online.
        """

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        print('switch_delete')
        """
        Event handler indicating a switch has been removed
        """

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        # print('host_add')
        host.append(ev.host)
        # print(ev.host.port)
        attributes = vars(ev.host.port)
        # print(attributes)
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        # print('link_add')
        link_between_switch.append(ev.link)
        attributes = vars(ev.link.src)
        # print(attributes)
        attributes = vars(ev.link.dst)
        # print(attributes)
        # print(ev.link.dst.name.decode())
        """
        Event handler indicating a link between two switches has been added
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating when a link between two switches has been deleted
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        print('port modify')
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        # TODO:  Update network topology and flow rules

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
                    print(pkt)
                # Dijkstra()
                # TODO: handle other protocols like ARP
                pass
            else:
                DHCPServer.handle_dhcp(datapath, inPort, pkt)
            return
        except Exception as e:
            self.logger.error(e)



class Graph:
    def __init__(self, num_of_vertices):
        self.vertices = num_of_vertices
        # 距离表
        self.edges = [[-1 for i in range(num_of_vertices)] for j in range(num_of_vertices)]
        # 记录被访问过的节点
        self.visited = []

    def add_edge(self, u, v):
        # 记录u，v两节点之间的距离
        # 要注意的是如果是有向图只需定义单向的权重
        # 如果是无向图则需定义双向权重
        self.edges[u-1][v-1] = 1
        self.edges[v-1][u-1] = 1

    def dijkstra(self, start_vertex):
        # 开始时定义源节点到其他所有节点的距离为无穷大
        D = {v: float('inf') for v in range(self.vertices)}
        # 源节点到自己的距离为0
        D[start_vertex] = 0
        # 优先队列
        pq = PriorityQueue()
        pq.put((0, start_vertex))
        # 记录每个节点的前节点，便于回溯
        previousVertex = {}

        while not pq.empty():
            # 得到优先级最高的节点，也就是前节点到其他节点距离最短的节点作为当前出发节点
            (dist, current_vertex) = pq.get()
            # 标记已访问过的节点(最有路径集合)
            self.visited.append(current_vertex)

            for neighbor in range(self.vertices):
                # 邻居节点之间距离不能为-1
                if self.edges[current_vertex][neighbor] != -1:
                    distance = self.edges[current_vertex][neighbor]
                    # 已经访问过的节点不能再次被访问
                    if neighbor not in self.visited:
                        # 更新源节点到其他节点的最短路径
                        old_cost = D[neighbor]
                        new_cost = D[current_vertex] + distance
                        if new_cost < old_cost:
                            # 加入优先队列
                            pq.put((new_cost, neighbor))
                            D[neighbor] = new_cost
                            previousVertex[neighbor] = current_vertex
        return D, previousVertex


def Dijkstra():
    g = Graph(len(switch)+len(host))
    for link in link_between_switch:
        g.add_edge(link.src.dpid, link.dst.dpid)
    for i in range(len(host)):
        g.add_edge(i+1+len(switch),host[i].port.dpid)
    D, previousVertex = g.dijkstra(0)
    # print(previousVertex)
    # 每个节点的前节点，可通过回溯得到最短路径
    for vertex in range(len(D)):
        print(f"distance from vertex {0} to vertex {vertex} is {D[vertex]}")

    # 节点名字与数字的对应表
    # dic = {0: 's', 1: 'v', 2: 'u', 3: 'w', 4: 't', 5: 'z'}
    # path = []
    # cheapest_path = []
    # key = 4
    # # 回溯，得到源节点到目标节点的最佳路径
    # while True:
    #     if key == 0:
    #         path.append(0)
    #         break
    #     else:
    #         path.append(key)
    #         key = previousVertex[key]
    # # 节点名字由数字转成字符
    # for point in path[:: -1]:
    #     cheapest_path.append(dic[point])
    # cheapest_path = "->".join(cheapest_path)
    #
    # print(f"distance from vertex {dic[0]} to vertex {dic[4]} is {D[4]},"
    #       f"the cheapest path is {cheapest_path}")
