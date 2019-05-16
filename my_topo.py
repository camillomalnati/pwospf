from mininet.topo import Topo


class TwoSwitchTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        switch1 = self.addSwitch("s1")
        cpu_1 = self.addHost(
            "c1", ip="10.0.0.1", mac="00:00:00:00:00:01"  # try to take the address out
        )
        host1_1 = self.addHost("h1", ip="10.0.0.3", mac="00:00:00:00:00:03")
        self.addLink(host1_1, switch1, port2=3)
        self.addLink(cpu_1, switch1, port2=1)

        switch2 = self.addSwitch("s2")
        cpu_2 = self.addHost("c2", ip="10.0.0.2", mac="00:00:00:00:00:02")
        host2_1 = self.addHost("h2", ip="10.0.0.4", mac="00:00:00:00:00:04")
        self.addLink(host2_1, switch2, port2=3)
        self.addLink(cpu_2, switch2, port2=1)

        self.addLink(switch1, switch2, port1=2, port2=2)

        switch3 = self.addSwitch("s3")
        cpu_3 = self.addHost("c3", ip="10.0.0.5", mac="00:00:00:00:00:05")
        host3_1 = self.addHost("h3", ip="10.0.0.6", mac="00:00:00:00:00:06")
        self.addLink(host3_1, switch3, port2=3)
        self.addLink(cpu_3, switch3, port2=1)

        self.addLink(switch2, switch3, port1=4, port2=4)

        # self.addLink(switch1, switch3, port1=4, port2=4)
        # self.addLink(switch2, switch3, port1=5, port2=5)
        # host3_1 = self.addHost("h3")
        # self.addLink(host3_1, switch3)
