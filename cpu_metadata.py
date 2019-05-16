from scapy.fields import BitField, ByteField, ShortField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

TYPE_CPU_METADATA = 0x080A


class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [
        ByteField("fromCPU", 0),
        ShortField("origEtherType", None),
        ShortField("srcPort", None),
    ]


bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
