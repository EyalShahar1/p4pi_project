import threading
from select import select
from scapy.all import conf, ETH_P_ALL, MTU, plist, Packet, Ether, IP, ARP, sendp
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, LenField, IntField, ShortField, LongField, IntEnumField, PacketListField
from threading import Thread, Event
from queue import Queue
import time

import p4runtime_lib.switch

ARP_OP_REPLY = 0x0002
ARP_OP_REQ = 0x0001
ARP_TIMEOUT = 30
HELLO_TYPE = 0x01
LSU_TYPE = 0x04
OSPF_PROT_NUM = 0x59
PWOSPF_HELLO_DEST = '224.0.0.5'
TYPE_CPU_METADATA = 0x080a
BROADCAST_MAC_ADDR = 'ff:ff:ff:ff:ff:ff'

INVALID_ROUTER_ID = 0
HELLOINT_IN_SECS = 10
INITIAL_HELLOINT = 3 * HELLOINT_IN_SECS
LSUINT_IN_SECS = 30
INITIAL_LSUINT = 3 * LSUINT_IN_SECS
# For simplicity, we defined the entire network as one area with the same area ID
AREA_ID = 1
VERSION_NUM = 2
INVALID_SEQUENCE_NUM = 0


# This function "sniffs" for packets.
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


# This class defines a neighbor, which is in reality an interface of another router. The neighbor is defined by an IP
# address (of the interface) and a router ID (of the router this interface belongs to)
class Neighbor:
    def __init__(self, router_id, ip_addr):
        self.router_id = router_id
        self.ip_addr = ip_addr
        self.uptime_counter = AtomicCounter(initial = INITIAL_HELLOINT)


# This class defines an interface, which is an abstract entity that defines the conenction between a router and one of
# its links. The interface is defined by its IP address, its subnet mask, the interval for sending out HELLO packets to
# all its neighbors (which in actuality is constant for the entire network), and its port number.
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
        self.helloint = helloint

        # The port number associated with this interface
        self.port = port

        # Every instance starts with an empty list of neighbors
        self.neighbors = {}

    def add_neighbor(self, neighbor_router_id, neighbor_ip):
        new_neighbor = Neighbor(neighbor_router_id, neighbor_ip)
        # Add neighbor to interface's neighbor list
        self.neighbors[neighbor_ip] = new_neighbor

    # NAAMA TODO - decide if I need to lock this list
    def remove_neighbor(self, neighbor_ip):
        del self.neighbors[neighbor_ip]




# This class defines a thread that handles incoming ARP packets
class ARPManager(Thread):
    def __init__(self, cntrl):
        super(ARPManager, self).__init__()
        self.cntrl = cntrl
        self.pkt_queue = Queue()


    def add_forwarding_entry(self, dst_ip_addr, dst_mac_addr, egress_port):
        # Create the table entry
        table_entry = p4runtime_lib.helper.P4InfoHelper.buildTableEntry(
            table_name = "MyIngress.forwarding_table",
            match_fields = {"meta.next_hop_ip_add": (dst_ip_addr, 32)},
            action_name = "MyIngress.ipv4_forward",
            action_params = {
                "next_hop": dst_mac_addr,
                "port": egress_port
                }
        )

        # Write entry to table
        p4runtime_lib.switch.SwitchConnection.WriteTableEntry(table_entry)


    def run(self):
        while True:
            # Consume packets from queue
            pkt = self.pkt_queue.get()

            # Check if packet is an ARP request
            if pkt[ARP].op == ARP_OP_REQ:

                # Check if the destination IP matches the interface's IP
                for interface in self.cntrl.interfaces:
                    if pkt[IP].dst == interface.ip_addr:
                        # Build ARP reply
                        arp_reply_pkt = Ether(src = self.cntrl.MAC, dst = pkt[Ether].src) / ARP(
                            op = ARP_OP_REPLY,
                            hwsrc = self.cntrl.MAC,
                            psrc = pkt[ARP].pdst,
                            hwdst = pkt[ARP].hwsrc,
                            pdst = pkt[ARP].psrc)
                        
                        # Send out ARP reply
                        self.cntrl.send_pkt(arp_reply_pkt)

            # Check if packet is an ARP reply
            # NAAMA TODO - I assume here that the dst MAC was checked in data plane and this is addressed to me
            elif pkt[ARP].op == ARP_OP_REPLY:

                # Add the new information to the forwarding table
                self.add_forwarding_entry(
                    dst_ip_addr = pkt[ARP].psrc,
                    dst_mac_addr = pkt[ARP].hwsrc,
                    egress_port = pkt[CPUMetadata].ingressPort
                )


class HelloPacketSender(Thread):
    def __init__(self, cntrl, helloint):
        super(HelloPacketSender, self).__init__()
        self.cntrl = cntrl
        self.helloint = helloint

    
    def run(self):
        while True:
            for interface in self.cntrl.interfaces:
                hello_pkt = Ether(src = self.cntrl.MAC,
                                  dst = BROADCAST_MAC_ADDR) / IP(
                                      src = interface.ip_addr,
                                      dst = PWOSPF_HELLO_DEST
                                      ) / PWOSPF(type = HELLO_TYPE) / Hello(
                                          mask = interface.subnet_mask,
                                          # NAAMA CHECK - might not be needed
                                          helloint = interface.helloint
                                          )
                self.cntrl.send_packet(hello_pkt)

            time.sleep(self.helloint)

            for interface in self.cntrl.interfaces:
                for neighbor in interface.neighbors.values():
                    new_uptime_value = neighbor.uptime_counter.decrement(HELLOINT_IN_SECS)
                    if new_uptime_value <= 0:
                        interface.remove_neighbor(neighbor.ip_addr)
            


# This class defines a thread that handles sending out periodic HELLO packets and updating neighbors 
class HelloManager(Thread):
    def __init__(self, cntrl):
        super(HelloManager, self).__init__()
        self.cntrl = cntrl
        self.pkt_queue = Queue()


    def run(self):
        hello_pkt_sender = HelloPacketSender(self.cntrl, HELLOINT_IN_SECS)
        hello_pkt_sender.start()


        while True:
            # Consume packets from queue
            pkt = self.pkt_queue.get()

            for interface in self.cntrl.interfaces:
                # Find the ingress interface using the ingress port
                if interface.port == pkt[CPUMetadata].ingressPort:
                    # Check if the interface already knows this neighbor
                    neighbor = interface.neighbors.get(pkt[IP].src)
                    if neighbor is not None:
                        neighbor.uptime_counter.set_value(INITIAL_HELLOINT)

                    else:
                        # If neighbor not found, add it
                        interface.add_neighbor(pkt[PWOSPF]["router ID"], pkt[IP].src)
                    
                    break


class LsuPacketSender(Thread):
    def __init__(self, cntrl, lsuint):
        super(LsuPacketSender, self).__init__()
        self.cntrl = cntrl
        self.lsuint = lsuint

    def run(self):
        while True:
            for interface in self.cntrl.interfaces:
                # Create LSU packet
                lsu_pkt = Ether(src = self.cntrl.MAC,
                                dst = BROADCAST_MAC_ADDR) / IP(
                                src = interface.ip_addr,
                                dst = PWOSPF_HELLO_DEST
                                ) / PWOSPF(type = LSU_TYPE) / LSU(
                                    seq = self.cntrl.lsu_counter.get_value(),
                                    ads = self.cntrl.get_lsu_ads()
                                    )
                # Send LSU packet
                self.cntrl.send_pkt(lsu_pkt)

            time.sleep(self.lsuint)


class TopologyNeighbor():
    def __init__(self, router_id, subnet, mask):
        self.router_id = router_id
        self.subnet = subnet
        self.mask = mask
        self.seq_num = INVALID_SEQUENCE_NUM
        self.lsu_counter = AtomicCounter(initial = INITIAL_LSUINT)
        self.neighbors = {}


class LSUManager(Thread):
    def __init__(self, cntrl, lsuint):
        super(LSUManager, self).__init__()
        self.lsuint = lsuint
        self.cntrl = cntrl
        self.pkt_queue = Queue()

        # An adjency list - a dictionary of Topology routers (with the key being the router ID), each holding a list
        # of topology router neighbors (meaning their router ID)
        # NAAMA TODO - how to initially fill this?
        self.topology = {}

    def run(self):
        lsu_pkt_sender = LsuPacketSender(self.cntrl, self.lsuint)
        lsu_pkt_sender.start()

        while True:
            # Consume packets from queue
            pkt = self.pkt_queue.get()

            src_router_id = pkt[PWOSPF]["Router ID"]

            if src_router_id == self.cntrl.routerID:
                continue
            
            src_router_adjency_list = self.topology.get(src_router_id)

            if src_router_adjency_list is None:
                src_router_adjency_list = []

            curr_seq_num = pkt[LSU].sequence

            if src_router_adjency_list[0].seq_num == curr_seq_num:
                continue




class AtomicCounter:
    def __init__(self, initial=0):
        self.value = initial
        self.lock = threading.Lock()

    def increment(self, amount = 1):
        with self.lock:
            self.value += amount
            return self.value
        
    def decrement(self, amount = 1):
        with self.lock:
            self.value -= amount
            return self.value
        
    def get_value(self):
        with self.lock:
            return self.value
        
    def set_value(self, new_value):
        with self.lock:
            self.value = new_value
            return self.value


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
        self.intfs = interfaces

        # The interval in seconds between link state update broadcasts
        # TODO: should this be hard coded? is the default in this func correct?
        self.lsuint = lsuint

        # TODO: what do we use this for?
        self.start_wait = start_wait

        # NAAMA TODO - not sure this is needed
        self.stop_event = Event()

        self.arp_manager = None
        self.hello_manager = None
        self.lsu_manager = None

        self.lsu_counter = AtomicCounter()


    def process_pkt(self, pkt):
        if ARP in pkt:
            self.arp_manager.pkt_queue.put(pkt)
        elif Hello in pkt:
            self.hello_manager.pkt_queue.put(pkt)
        elif LSU in pkt:
            self.lsu_manager.pkt_queue.put(pkt)


    def sniff_interface(self):
        return sniff(store = False, prn = self.process_pkt, stop_event = self.stop_event, refresh = 0.1)
    

    def send_pkt(self, pkt):
        sendp(pkt, iface = self.sw)


    def get_lsu_seq(self):
        self.lsu_seq = self.lsu_seq + 1
        return self.lsu_seq
    

    def get_lsu_ads(self):
        # NAAMA TODO - implement
        pass


    def run(self):
        # Start ARP manager
        arp_manager = ARPManager(self)
        arp_manager.start()
        self.arp_manager = arp_manager

        # Start HELLO manager
        hello_manager = HelloManager(self)
        hello_manager.start()
        self.hello_manager = hello_manager

        # Start LSU manager
        lsu_manager = LSUManager(self, self.lsuint)
        lsu_manager.start()
        self.lsu_manager = lsu_manager

        # NAAMA TODO - need to sniff all interfaces
        self.sniff_interface()

        


# TODO: not sure what this should contain
class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [
        ShortField("ingressPort", 0)
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