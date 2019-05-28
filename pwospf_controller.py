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
        # self.oldRoutingTable = {}
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

        self.forwarding_ports[me] = 1  # cpu port

        for entry in self.host_connected:
            self.links.add((me, entry[0]))
            self.nodes.add(entry[0])
            self.forwarding_ports[entry[0]] = entry[2]
            self.neighbours.add(entry[0])
            self.routingTable[entry[0]] = entry[2]

        # for node in self.nodes:
        #     self.routingTable[node] = {}

        # for node in self.nodes:
        #     self.routingTable[node][node] = 0

        # for link in self.links:
        #     self.routingTable[link[0]][link[1]] = 1
        #     self.routingTable[link[1]][link[0]] = 1

        # self.oldRoutingTable = self.routingTable

    def computeDijkstra(self):

        me = self.controller_address
        links = self.links
        nodes = self.nodes
        neighbours = self.neighbours
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
        unvisited.remove(me)

        while len(unvisited) > 0:
            mininum = float("inf")
            checking = None
            for node in unvisited:
                if dist[node] <= mininum:
                    checking = node
                    mininum = dist[node]

            unvisited.remove(checking)

            neighbours_of_unvisited = set()
            for link in links:
                if checking in link:
                    if link[0] == checking:
                        neighbours_of_unvisited.add(link[1])
                    else:
                        neighbours_of_unvisited.add(link[0])

            if me in neighbours_of_unvisited:
                neighbours_of_unvisited.remove(me)

            for node in neighbours_of_unvisited:
                if dist[node] + dist[checking] < dist[checking]:
                    dist[checking] = dist[node] + dist[checking]
                    prev[checking] = node

        for key, value in prev.items():
            if key != me and value != None:
                if self.sw.name == "s2":
                    print(
                        "++++++++", self.routingTable, self.forwarding_ports, key, value
                    )
                if key in self.forwarding_ports:
                    self.routingTable[key] = self.forwarding_ports[key]
                else:
                    self.routingTable[key] = self.forwarding_ports[value]

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

    def IP2Int(self, ip):
        o = map(int, ip.split("."))
        res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
        return res

    def Int2IP(self, ipnum):
        o1 = int(ipnum / 16777216) % 256
        o2 = int(ipnum / 65536) % 256
        o3 = int(ipnum / 256) % 256
        o4 = int(ipnum) % 256
        return "%(o1)s.%(o2)s.%(o3)s.%(o4)s" % locals()

    def sendLSUPackets(self):
        if self.sw.name == "s2":
            print("new routing")
        for node in self.neighbours:
            for node1 in self.neighbours:
                if node != node1:
                    subnet = self.IP2Int(node1)
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
                            subnet=subnet,  # should put the converted route here
                            mask=0xFFFFFFFF,
                            router_id=0,
                        )
                    )
                    self.send(lsu)

    def sendRegularlyHello(self):
        self.sendHelloPacket()
        Timer(self.hello_timer, self.sendHelloPacket).start()

    def handlePWOSPFHello(self, pkt):
        source = str(pkt[IP].src)
        self.nodes.add(source)
        self.neighbours.add(source)
        if self.sw.name == "s2":
            print("I'm s2: new hello from", source)
            print(self.links)
            print(self.nodes)

        if not (
            (self.controller_address, source) in self.links
            or (source, self.controller_address) in self.links
        ):
            self.links.add((self.controller_address, source))
            # if self.sw.name == "s2":
            #     print("added: ", (self.controller_address, source))
            #     print("new nodes are:", (self.nodes))

        if source not in self.forwarding_ports:
            self.forwarding_ports[source] = pkt[CPUMetadata].srcPort

            #     self.computeDijkstra()
            if self.sw.name == "s2":
                self.checkForLSU()

    def checkForLSU(self):
        if self.sw.name == "s2":
            print("before", self.routingTable)
        old_rt = self.routingTable.copy()
        self.computeDijkstra()
        if self.sw.name == "s2":
            print("after", self.routingTable)
            print("oldafter", old_rt)
        if old_rt != self.routingTable:
            self.sendLSUPackets()

    def handlePWOSPFLSU(self, pkt):
        me = self.controller_address
        source = pkt[IP].src
        updated = self.Int2IP(pkt[PWOSPF_ADV].subnet)
        self.nodes.add(source)
        self.nodes.add(updated)  # need to be checked maybe

        if not ((source, updated) in self.links or (source, updated) in self.links):
            self.links.add((source, updated))

        self.checkForLSU()

    def handlePkt(self, pkt):
        if pkt[IP].src == self.controller_address:
            return
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
        # Timer(30, self.sendLSUPackets).start()

    def start(self, *args, **kwargs):
        super(PWOSPFController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(PWOSPFController, self).join(*args, **kwargs)
