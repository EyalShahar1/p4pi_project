import threading
from select import select
from scapy.all import conf, ETH_P_ALL, MTU, plist, Packet, Ether, IP, ARP, sendp
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, LenField, IntField, ShortField, LongField, IntEnumField, PacketListField
from threading import Thread, Event
import time

ARP_OP_REPLY = 0x0002
ARP_OP_REQ = 0x0001
ARP_TIMEOUT = 30
HELLO_TYPE = 0x01
LSU_TYPE = 0x04
OSPF_PROT_NUM = 0x59
PWOSPF_HELLO_DEST = '224.0.0.5'
TYPE_CPU_METADATA = 0x080a
BROADCAST_MAC_ADDR = 'ff:ff:ff:ff:ff:ff'

# NAAMA TODO - check if needed
# NAAMA CHECK - can also be 0xffffffff
# INVALID_ROUTER_ID = 0
HELLOINT_IN_SECS = 10
AREA_ID = 1
VERSION_NUM = 2
INVALID_SEQUENCE_NUM = 0

# READ THIS FIRST
# The way this works as far as I can understand - the router controller holds all the info of the router -
# the tables and everything - and it's a thread. It holds an ARP manager (thread) that it forwards all ARP packets
# to, a HELLO manager (thread) that creates all HELLO packets and manages incoming one,
# and an LSU manager (thread) that creates all LSA packets.


# This function "sniffs" for packets.
# TODO - think if we want to open and close the socket
def sniff(store=False, prn=None, lfilter=None, stop_event=None, refresh=.1, *args, **kwargs):
    # Listen for packets
    s = conf.L2listen(type=ETH_P_ALL, *args, **kwargs)
    lst = []
    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            sel = select([s], [], [], refresh)
            if s in sel[0]:
                # Receive data from socket as bytes object, MTU "infinite"
                p = s.recv(MTU)
                if p is None:
                    break
                if lfilter and not lfilter(p):
                    # Possible filtering of the packet
                    continue
                if store:
                    # Add the packet to the list
                    lst.append(p)
                if prn:
                    r = prn(p)
                    if r is not None:
                        print(r)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
    return plist.PacketList(lst, "Sniffed")


class Neighbor:
    def __init__(self, router_id, ip_addr):
        self.router_id = router_id
        self.ip_addr = ip_addr


class Interface:
    def __init__(self, ip_addr, subnet_mask, helloint, port):
        # The IP address of the interface
        # 32-bit
        self.ip_addr = ip_addr

        # The subnet mask of the interface
        # 32-bit
        self.subnet_mask = subnet_mask

        # Interval in seconds between HELLO messages
        # 16-bit
        # NAAMA TODO: maybe we assign all interfaces the same hard coded number
        self.helloint = helloint

        # The port number associated with this interface
        # NAAMA TODO - needed?
        self.port = port

        # Every instance starts with an empty list of neighbors
        self.neighbors = []

    def addNeighbor(self, neighbor_router_id, neighbor_ip):
        new_neighbor = Neighbor(neighbor_router_id, neighbor_ip)
        # Add neighbor to interface's neighbor list
        self.neighbors.append(new_neighbor)

    def removeNeighbor(self):
        # NAAMA TODO - function params? implement
        pass


class ARPManager(Thread):
    def __init__(self, cntrl, interface):
        super(ARPManager, self).__init__()
        self.cntrl = cntrl
        # NAAMA TODO - not sure this is the way to do this, should I have arp manager per interface or just 1?
        self.interface = interface


    def run(self):
        while True:
            # NAAMA TODO - not sure these 2 next lines works
            pkt = self.ctrl.sniff_interface()
            if ARP in pkt:
                # Check if packet is an ARP request
                if pkt[ARP].op == ARP_OP_REQ:
                    # Check if the destination IP matches the interface's IP
                    if pkt[IP].dst == self.interface.ip_addr:
                        # Build ARP reply
                        arp_reply_pkt = Ether(src = self.cntrl.MAC, dst = pkt[Ether].src) / ARP(
                            op = ARP_OP_REPLY,
                            hwsrc = self.cntrl.MAC,
                            psrc = pkt[ARP].pdst,
                            hwdst = pkt[ARP].hwsrc,
                            pdst = pkt[ARP].psrc)
                        # Send out ARP reply
                        self.cntrl.send_pkt(arp_reply_pkt)


class HelloManager(Thread):
    def __init__(self, cntrl):
        super(HelloManager, self).__init__()
        self.cntrl = cntrl
        self.interfaces = self.cntrl.interfaces


    def run(self):
        while True:
            # Create HELLO packets
            for interface in self.interfaces:
                hello_pkt = Ether(src = self.cntrl.MAC,
                                    dst = BROADCAST_MAC_ADDR) / IP(
                                        src = interface.ip_addr,
                                        dst = PWOSPF_HELLO_DEST
                                        # NAAMA TODO - make sure this works
                                    ) / PWOSPF(type = HELLO_TYPE) / Hello(
                                        mask = interface.subnet_mask,
                                        # NAAMA CHECK - maybe not needed
                                        helloint = interface.helloint
                                    )
                self.cntrl.send_packet(hello_pkt)
            # NAAMA TODO - maybe add constant time here, this is kinda akum
            time.sleep(interface[0].helloint)


class LSUManager(Thread):
    def __init__(self, cntrl, lsuint):
        super(LSUManager, self).__init__()
        self.lsuint = lsuint
        self.cntrl = cntrl
        self.interfaces = self.cntrl.interfaces

    # NAAMA TODO - needs to create a fiber that'll create and send LSU packets (the current content of the run
    # func), and instead in the run func we need to handle LSU packets.
    # This class will need to hold the adjency list and run djikstra

    def run(self):
        while True:
            for interface in self.interfaces:
                for neighbor in interface.neighbors:
                    # Create LSU packet
                    lsu_pkt = Ether(src = self.cntrl.MAC,
                                    dst = BROADCAST_MAC_ADDR) / IP(
                                        src = interface.ip_addr,
                                        dst = neighbor.ip_addr
                                    ) / PWOSPF(type = LSU_TYPE) / LSU(
                                        seq = self.cntrl.get_lsu_seq(),
                                        ads = self.cntrl.get_lsu_ads()
                                    )
                    # Send LSU packet
                    self.cntrl.send_pkt(lsu_pkt)
            time.sleep(self.lsuint)


# TODO - Router ID is by convention the IP address of the 0th interface of the router - we need to figure
#  out to get that
class RouterController(Thread):

    def __init__(self, sw, routerID, MAC, areaID, interfaces, lsuint=2, start_wait=0.3):
        # Calling the superclass constructor
        super(RouterController, self).__init__()

        # NAAMA TODO: no clue what this is
        self.sw = sw

        # The router ID of the router
        # 32-bit
        self.routerID = routerID

        # The MAC address of the router
        # 48-bit
        # TODO: where tf do I get this from
        self.MAC = MAC

        # The area ID of the router
        # 32-bit
        # TODO: should this be hard coded? this'll probably be all one area
        self.areaID = areaID

        # List of router interfaces
        self.intfs = intfs

        # The interval in seconds between link state update broadcasts
        # TODO: should this be hard coded? is the default in this func correct?
        self.lsuint = lsuint

        # TODO: what do we use this for?
        self.start_wait = start_wait

        # NAAMA TODO - not sure this is needed
        self.stop_event = Event()

    lsu_seq = 0

    def run(self):
        # Start ARP manager for every interface
        # NAAMA TODO - maybe in list comprehension create an array
        for interface in self.interfaces:
            arp_manager = ARPManager(self, interface)
            arp_manager.start()
        
        # Start HELLO manager
        hello_manager = HelloManager(self)
        hello_manager.start()

        # Start LSU manager
        lsu_manager = LSUManager(self, self.lsuint)
        lsu_manager.start()

    def sniff_interface(self):
        # NAAMA TODO - maybe we should store? and send to managers in queues?
        return sniff(store = False, prn = None, stop_event = self.stop_event, refresh = 0.1)
    
    def send_pkt(self, pkt):
        sendp(pkt, iface = self.sw)

    def get_lsu_seq(self):
        self.lsu_seq = self.lsu_seq + 1
        return self.lsu_seq
    
    def get_lsu_ads(self):
        # NAAMA TODO - implement
        pass


# TODO: not sure what this should contain
class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [
        # TODO: Create CPUMetadata packet fields
    ]


class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [
        ByteField("version", VERSION_NUM),
        # TODO - made the default 0 so we won't misidentify packets, might need to change
        ByteField("type", 0),
        # TODO - this needs to include the length of the header, not just the payload
        LenField("packet length", 0),
        IntField("router ID", 0),
        # TODO - add hard coded area ID
        IntField("area ID", AREA_ID),
        ShortField("checksum", 0),
        ShortField("autype", 0),
        LongField("authentication", 0)
    ]


class Hello(PWOSPF):
    name = "Hello"
    fields_desc = [
        # NAAMA TODO - might need to be 0xFFFFFFFF
        # NAAMA TODO - maybe IPField?
        IntField("network mask", '255.255.255.0'),
        ShortField("HelloInt", HELLOINT_IN_SECS),
        # NAAMA TODO - is this needed?
        ShortField("padding", 0)
    ]


class LSUad(Packet):
    name = "LSUad"
    fields_desc = [
        # NAAMA TODO - maybe IPField? also make constant
        IntField("subnet", '0.0.0.0'),
        # NAAMA TODO - maybe IPField? also make constant
        IntField("mask", '255.255.255.0'),
        IntField("router ID", 0)
    ]


class LSU(PWOSPF):
    name = "LSU"
    fields_desc = [
        IntField("sequence", INVALID_SEQUENCE_NUM),
        # NAAMA TODO - needed?
        IntEnumField("TTL", 0),
        LongField("advertisements", 0),
        # NAAMA TODO - maybe fieldlistfield
        PacketListField("LSUads", None, LSUad)
        # option - FieldListField("ads", [], LSUad, count_from=lambda pkt: len(pkt.ads)
    ]


bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)
bind_layers(IP, PWOSPF, proto=OSPF_PROT_NUM)
bind_layers(PWOSPF, Hello, type=HELLO_TYPE)
bind_layers(PWOSPF, LSU, type=LSU_TYPE)

if __name__ == "__main__":
    interfaces = []
    router_controller = RouterController("eth0", "", "", AREA_ID, interfaces)
    router_controller.start()