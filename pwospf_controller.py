from threading import Thread, Event, Timer
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from pwospf_protocol import PWOSPF_HEADER, PWOSPF_HELLO, PWOSPF_LSU, PWOSPF_ADV
import time

import pdb

OSPF_HELLO = 1
OSPF_LSU = 4
ALLSPFRouters = "224.0.0.5"


class PWOSPFController(Thread):
    def __init__(
        self,
        sw,
        controller_address,
        rid,
        area_id,
        host_connected,
        network_mask,
        fr,
        network,
        hello_timer,
        start_wait=5,
    ):
        super(PWOSPFController, self).__init__()
        self.sw = sw
        self.controller_address = controller_address
        self.rid = rid
        self.area_id = area_id
        self.mask = network_mask
        self.start_wait = start_wait  # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name  # 0 is loopback
        self.host_connected = host_connected
        self.routingTable = {}
        self.links = set()
        self.nodes = set()
        self.neighbours = set()
        self.forwarding_ports = {}
        self.stop_event = Event()
        self.addForwardingRules(fr)
        self.initialise_routing_table()
        self.computeDijkstra()
        self.setupMulticast(10)
        self.hello_timer = hello_timer

    def initialise_routing_table(self):
        me = self.controller_address

        self.nodes.add(me)

        for entry in self.host_connected:
            self.links.add((me, entry[0]))
            self.nodes.add(entry[0])
            self.forwarding_ports[entry[0]] = entry[2]
            self.neighbours.add(entry[0])

        for node in self.nodes:
            self.routingTable[node] = {}

        for node in self.nodes:
            self.routingTable[node][node] = 0

        for link in self.links:
            self.routingTable[link[0]][link[1]] = 1
            self.routingTable[link[1]][link[0]] = 1

    def computeDijkstra(self):

        me = self.sw.name
        links = self.links
        nodes = self.nodes
        unvisited = set()
        dist = {}
        prev = {}

        for node in nodes:
            unvisited.add(node)
            if (node, me) in links or (me, node) in links:
                dist[node] = 1
                prev[node] = me
            else:
                dist[node] = float("inf")
                prev[node] = None

        dist[me] = 0

        while len(unvisited) > 0:
            mininum = float("inf")
            checking = None
            for node in unvisited:
                if dist[node] <= mininum:
                    checking = node
                    mininum = dist[node]

            unvisited.remove(checking)
            for node, distance in self.routingTable[checking].items():
                if node in unvisited:
                    new_route = dist[checking] + distance
                    if new_route < dist[node]:
                        # print("new best route:", node, new_route, dist[node])
                        dist[node] = new_route
                        prev[node] = checking

    def setupMulticast(self, mgid):
        self.sw.insertTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={"hdr.ipv4.dstAddr": [ALLSPFRouters, 32]},
            action_name="MyIngress.set_mgid",
            action_params={"mgid": mgid},
        )
        self.sw.addMulticastGroup(mgid=mgid, ports=range(2, 6))  # we need to fix this

    def addForwardingRules(self, fr):
        for entry in fr:
            self.sw.insertTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={"hdr.ipv4.dstAddr": entry[0]},
                action_name="MyIngress.ipv4_forward",
                action_params={"dstAddr": entry[1], "port": entry[2]},
            )

    def sendHelloPacket(self):
        hello = (
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / CPUMetadata(fromCPU=1)
            / IP(src=self.controller_address, dst=ALLSPFRouters)
            / PWOSPF_HEADER(
                type=1, packet_length=32, router_ID=self.rid, aread_ID=self.area_id
            )
            / PWOSPF_HELLO(network_mask=self.mask)
        )

        self.send(hello)

    def sendLSUPackets(self):
        if self.sw.name == "s2":

            for node in self.neighbours:
                for route in self.routingTable[self.controller_address]:
                    lsu = (
                        Ether(dst="ff:ff:ff:ff:ff:ff")
                        / CPUMetadata(fromCPU=1)
                        / IP(src=self.controller_address, dst=node)
                        / PWOSPF_HEADER(
                            type=4,
                            packet_length=32,
                            router_ID=self.rid,
                            aread_ID=self.area_id,
                        )
                        / PWOSPF_LSU()
                        / PWOSPF_ADV(
                            subnet=0x0A000005,  # should put the converted route here
                            mask=0xFFFFFFFF,
                            router_id=self.rid,
                        )
                    )
                    self.send(lsu)

    def sendRegularlyHello(self):
        self.sendHelloPacket()
        Timer(self.hello_timer, self.sendHelloPacket).start()

    def updateRoutingTable(self, new_entry):
        print("updating routing table with new entry: ", new_entry)
        print(self.routingTable)
        self.routingTable[self.controller_address][new_entry] = 1
        self.routingTable[new_entry] = {}
        self.routingTable[new_entry][self.controller_address] = 1
        print(self.routingTable)
        self.sendLSUPackets()

    def handlePWOSPFHello(self, pkt):
        source = str(pkt[IP].src)
        self.nodes.add(source)
        self.links.add((self.controller_address, source))
        if source not in self.routingTable:
            self.updateRoutingTable(source)
            self.forwarding_ports[source] = pkt[CPUMetadata].srcPort
            print(self.forwarding_ports)
            self.computeDijkstra()
            print("new entry, recomputing dijkstra:")
            print(self.routingTable)

    def handlePWOSPFLSU(self, pkt):
        print("NEW LSU")
        pkt.show2()

    def handlePkt(self, pkt):
        if PWOSPF_HEADER in pkt:
            if pkt[PWOSPF_HEADER].type == OSPF_HELLO:
                self.handlePWOSPFHello(pkt)
            elif pkt[PWOSPF_HEADER].type == OSPF_LSU:
                self.handlePWOSPFLSU(pkt)

    def runSniff(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCPU = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        if self.sw.name == "s2":
            print("I'm s2: sniffing")

        elif self.sw.name == "s3":
            print("I'm s3: sniffing")

        elif self.sw.name == "s1":
            print("I'm s1: sniffing")

        Thread(target=self.runSniff).start()
        Thread(target=self.sendRegularlyHello).start()

    def start(self, *args, **kwargs):
        super(PWOSPFController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(PWOSPFController, self).join(*args, **kwargs)
