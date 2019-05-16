from scapy.all import *
import sys, os

TYPE_IPV4 = 0x0800
TYPE_OSPF = 89


class PWOSPF_HEADER(Packet):
    name = "pwospf header"
    fields_desc = [
        ByteField("version", 2),
        ByteEnumField("type", 2, {1: "Hello Packet", 4: "LS Update"}),
        ShortField("packet_length", 0),
        IntField("router_ID", 0),
        IntField("aread_ID", 0),
        ShortField("checksum", 0),
        ShortField("autype", 0),
        LongField("autentication", 0),
    ]

    # def mysummary(self):
    #     return self.sprintf("pid=%pid%, dst_id=%dst_id%")


class PWOSPF_HELLO(Packet):
    name = "pwospf hello"
    fields_desc = [
        IntField("network_mask", 0),
        ShortField("hello_int", 60),
        ShortField("padding", 0),
    ]


class PWOSPF_LSU(Packet):
    name = "pwospf lsu"
    fields_desc = [
        ByteField("version", 0),
        ByteField("type", 0),
        ShortField("packet_length", 0),
        IntField("router_ID", 0),
        IntField("area_ID", 0),
        ShortField("checksum", 0),
        ShortField("autype", 0),
        LongField("autentication", 0),
        ShortField("sequence", 0),
        ShortField("ttl", 0),
        IntField("adv_number", 0),
        IntField("adv", 0),
    ]


bind_layers(IP, PWOSPF_HEADER, proto=TYPE_OSPF)
bind_layers(PWOSPF_HEADER, PWOSPF_HELLO, type=1)
bind_layers(PWOSPF_HEADER, PWOSPF_LSU, type=4)
