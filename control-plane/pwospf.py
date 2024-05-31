import threading
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
LSU_TYPE = 0x04
OSPF_PROT_NUM = 0x59
PWOSPF_HELLO_DEST = '224.0.0.5'
TYPE_CPU_METADATA = 0x080a

# Naama - can also be 0xffffffff
INVALID_ROUTER_ID = 0

# Global variables
arp_in_queue = queue.Queue()
arp_out_queue = queue.Queue()
hello_in_queue = queue.Queue()
hello_out_queue = queue.Queue()
lsu_in_queue = queue.Queue()
lsu_out_queue = queue.Queue()

# READ THIS FIRST
# The way this works as far as I can understand - the router controller holds all the info of the router -
# the tables and everything - and it's a thread. It holds an ARP manager (thread) that it forwards all ARP packets
# to, a HELLO manager (thread) that creates all HELLO packets and manages incoming one,
# and an LSU manager (thread) that creates all LSA packets.


# This function "sniffs" for packets.
# TODO - think if we want to open and close the socket, or write prn func to add the packet to some queue
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
        # TODO: maybe we assign all interfaces the same hard coded number
        self.helloint = helloint

        # The port number associated with this interface
        # TODO - needed?
        self.port = port

        # Every instance starts with an empty list of neighbors
        self.neighbors = []

    def addNeighbor(self, neighbor_router_id, neighbor_ip):
        # TODO - pass helloint and port number
        new_neighbor = Neighbor(neighbor_router_id, neighbor_ip)
        self.neighbors.append(new_neighbor)


class ARPManager(Thread):
    def __init__(self, cntrl):
        super(ARPManager, self).__init__()
        self.cntrl = cntrl

    def run(self):
        while True:
            arp_packet = arp_in_queue.get()
            # create the required arp request with possible dupes, not sure if control or data plane need to do this
            # pass packets back to data plane (probably through control thread)
            # if packet is an arp request:
            # if the ip in packet matches our own - create ARP reply and pass back (probably to controller)
            # if it doesn't - do nothing (drop)
        return


class HelloManager(Thread):
    def __init__(self, cntrl, intf):
        super(HelloManager, self).__init__()
        self.cntrl = cntrl
        # List of interfaces, TODO - maybe hashtable for performance?
        self.intf = intf

    def sendHelloPackets(self):
        # TODO - implement
        pass

    def createHelloPacketSender(self):
        self.sendHelloPackets()
        # TODO - add start time
        t = threading.Timer(0, self.createHelloPacketSender)
        t.start()
        return

    def removeExpiredNeighbours(self):
        # TODO - implement
        pass

    def createExpiredNeighbourRemover(self):
        self.removeExpiredNeighbours()
        # TODO - add start time
        t = threading.Timer(0, self.createExpiredNeighbourRemover)
        t.start()
        return


    def run(self):
        while True:
            self.createHelloPacketSender()
            self.createExpiredNeighbourRemover()

            hello_packet = hello_in_queue.get()
            # TODO  - processing of packet
        return


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
