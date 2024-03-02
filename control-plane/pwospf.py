from select import select
from scapy.all import conf, ETH_P_ALL, MTU, plist, Packet, Ether, IP, ARP
from scapy.packet import Packet, bind_layers
from threading import Thread
import queue


ARP_OP_REPLY = 0x0002
ARP_OP_REQ = 0x0001
ARP_TIMEOUT = 30
HELLO_TYPE = 0x01
HELLO_TYPE = 0x01
ICMP_ECHO_REPLY_CODE = 0x00
ICMP_ECHO_REPLY_TYPE = 0x00
ICMP_HOST_UNREACHABLE_CODE = 0x01
ICMP_HOST_UNREACHABLE_TYPE = 0x03
ICMP_PROT_NUM = 0x01
LSU_TYPE = 0x04
OSPF_PROT_NUM = 0x59
OSPF_PROT_NUM = 0x59
PWOSPF_HELLO_DEST = '224.0.0.5'
TYPE_CPU_METADATA = 0x080a

# Naama - can also be 0xffffffff
INVALID_ROUTER_ID = 0

# READ THIS FIRST
# The way this works as far as I can understand - the router controller holds all the info of the router -
# the tables and everything - and it's a thread. It holds an ARP manager (thread) that it forwards all ARP packets
# to, a HELLO manager (thread) that creates all HELLO packets and manages incoming one,
# and an LSU manager (thread) that creates all LSA packets.


# Naama - seems like this is a func to receive packets from socket/port, prn is a func to apply to packets
# returns a list of packets named sniff
def sniff(store=False, prn=None, lfilter=None, stop_event=None, refresh=.1, *args, **kwargs):
    s = conf.L2listen(type=ETH_P_ALL, *args, **kwargs)
    lst = []
    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            sel = select([s], [], [], refresh)
            if s in sel[0]:
                p = s.recv(MTU)
                if p is None:
                    break
                if lfilter and not lfilter(p):
                    continue
                if store:
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


# This class is intended to be used in interface neighbour lists
class Neighbor:
    def __init__(self, router_id, ip_addr):
        self.router_id = router_id
        self.ip_addr = ip_addr


class Interface:
    # Every instance starts with an empty list of neighbors
    neighbors = []

    def __init__(self, ip_addr, subnet_mask, helloint, port):
        # The IP address of the interface
        # 32-bit
        self.ip_addr = ip_addr

        # The subnet mask of the interface
        # 32-bit
        self.subnet_mask = subnet_mask

        # Interval in seconds between HELLO messages
        # 16-bit
        # TODO: maybe we assign all interfaces the same hard coded number
        self.helloint = helloint

        # The port number associated with this interface
        self.port = port

    def addNeighbor(self, neighbor_router_id, neighbor_ip):
        new_neighbor = Neighbor(neighbor_router_id, neighbor_ip)
        self.neighbors.append(new_neighbor)


# TODO: I think cntrl is the router in which this thread is found
class ARPManager(Thread):
    def __init__(self, cntrl):
        super(ARPManager, self).__init__()
        self.cntrl = cntrl

    def run(self):
        # TODO: in pseudo code:
        # while true
        # consume ARP packet from some queue (probably one that belongs to the router controller)
        # if packet is a request from data plane to create an ARP request:
        # create as many ARP request packets as there are interfaces - 1
        # pass them to back to data plane (probably to controller)
        # if packet is an ARP request:
        # if the ip in packet matches our own - create ARP reply and pass back (probably to controller)
        # if it doesn't - do nothing (drop)
        return


# Naama - we're gonna treat this like a thread that has a list of interfaces
class HelloManager(Thread):
    def __init__(self, cntrl, intf):
        super(HelloManager, self).__init__()
        self.cntrl = cntrl
        self.intf = intf

    def run(self):
        # TODO: Handle Hello packets
        pass


# TODO: shouldn't this get a list of interfaces as well? or does it work based on existing
#  neighbours (probably the second option). lsuint should also probably a constant value
class LSUManager(Thread):
    def __init__(self, cntrl, lsuint):
        super(LSUManager, self).__init__()
        self.lsuint = lsuint
        self.cntrl = cntrl

    def run(self):
        return
        # TODO: Handle LSU packets


# TODO - Router ID is by convention the IP address of the 0th interface of the router - we need to figure
#  out to get that
class RouterController(Thread):

    def __init__(self, sw, routerID, MAC, areaID, intfs, lsuint=2, start_wait=0.3):
        # Calling the superclass constructor
        super(RouterController, self).__init__()

        # TODO: no clue what this is
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
        # TODO: should this be hard coded?
        self.lsuint = lsuint

        # TODO: what do we use this for?
        self.start_wait = start_wait

    def run(self):
        while True:
            packet_list = sniff()



# TODO: not sure what this should contain
class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [
        # TODO: Create CPUMetadata packet fields
    ]


class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [
        # TODO: Create PWOSPF packet fields
    ]


class Hello(Packet):
    name = "Hello"
    fields_desc = [
        # TODO: Create Hello packet fields
    ]


class LSUad(Packet):
    name = "LSUad"
    fields_desc = [
        # TODO: Create LSUad packet fields
    ]


class LSU(Packet):
    name = "LSU"
    fields_desc = [
        # TODO: Create LSU packet fields
    ]


bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)
bind_layers(IP, PWOSPF, proto=OSPF_PROT_NUM)
bind_layers(PWOSPF, Hello, type=HELLO_TYPE)
bind_layers(PWOSPF, LSU, type=LSU_TYPE)
