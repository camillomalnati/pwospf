# Camillo Malnati, 16.03.2019

from p4app import P4Mininet
from my_topo import TwoSwitchTopo
import sys
import time
from pwospf_controller import PWOSPFController


topo = TwoSwitchTopo()
net = P4Mininet(program="pwospf.p4", topo=topo)
net.start()

# Populate IPv4 forwarding table
def addForwardingRule(sw, host, port):
    sw.insertTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={"hdr.ipv4.dstAddr": ["10.0.0.%d" % host, 32]},
        action_name="MyIngress.ipv4_forward",
        action_params={"dstAddr": net.get("h%d" % host).intfs[0].mac, "port": port},
    )


s1, s2, h1, h2, c1, c2, s3, c3, h3 = (
    net.get("s1"),
    net.get("s2"),
    net.get("h1"),
    net.get("h2"),
    net.get("c1"),
    net.get("c2"),
    net.get("s3"),
    net.get("c3"),
    net.get("h3"),
)

# Topology addresses and ports


#   s3
#                                                       |
#                                                       |
#           .1      1 * - *  2                       2 * - * 1          .2
#            cpu------| s1|----------------------------| s2|--------cpu
#                     * - *                            * - *
#                       | 3                              | 3
#                       |                                |
#                       |                                |
#         10.0.0.3      | 3                            3 |  10.0.0.4
#                     * - *                            * - *
#                     | h1|                            | h2|
#                     * - *                            * - *

fr1 = [
    [["10.0.0.3", 32], net.get("h1").intfs[0].mac, 3],
    [["10.0.0.4", 32], net.get("h2").intfs[0].mac, 2],
    [["10.0.0.6", 32], net.get("h3").intfs[0].mac, 2],
    [["10.0.0.1", 32], net.get("c1").intfs[0].mac, 1],
    [["10.0.0.2", 32], net.get("c2").intfs[0].mac, 2],
    [["10.0.0.5", 32], net.get("c3").intfs[0].mac, 2],
]

fr2 = [
    [["10.0.0.3", 32], net.get("h1").intfs[0].mac, 2],
    [["10.0.0.4", 32], net.get("h2").intfs[0].mac, 3],
    [["10.0.0.6", 32], net.get("h3").intfs[0].mac, 4],
    [["10.0.0.2", 32], net.get("c2").intfs[0].mac, 1],
    [["10.0.0.1", 32], net.get("c1").intfs[0].mac, 2],
    [["10.0.0.5", 32], net.get("c3").intfs[0].mac, 4],
]

fr3 = [
    [["10.0.0.3", 32], net.get("h1").intfs[0].mac, 4],
    [["10.0.0.4", 32], net.get("h2").intfs[0].mac, 4],
    [["10.0.0.6", 32], net.get("h3").intfs[0].mac, 3],
    [["10.0.0.2", 32], net.get("c2").intfs[0].mac, 4],
    [["10.0.0.1", 32], net.get("c1").intfs[0].mac, 4],
    [["10.0.0.5", 32], net.get("c3").intfs[0].mac, 1],
]

# Start the pwospf controller
controller1 = PWOSPFController(
    s1, "10.0.0.1", 1, 1, [("10.0.0.3", 0xFFFFFFFF, 3)], 0xFFFFFF00, fr1, net, 60
)
controller1.start()

controller2 = PWOSPFController(
    s2, "10.0.0.2", 2, 1, [("10.0.0.4", 0xFFFFFFFF, 3)], 0xFFFFFF00, fr2, net, 60
)
controller2.start()

controller3 = PWOSPFController(
    s3, "10.0.0.5", 3, 1, [("10.0.0.6", 0xFFFFFFFF, 3)], 0xFFFFFF00, fr3, net, 60
)
controller3.start()

# addForwardingRule(s1, 1, 1)
# addForwardingRule(s1, 3, 3)
# addForwardingRule(s1, 4, 2)

# addForwardingRule(s2, 3, 2)
# addForwardingRule(s2, 4, 3)
# addForwardingRule(s2, 2, 1)


print("going to sleep")
while True:
    time.sleep(1)

print("done")
