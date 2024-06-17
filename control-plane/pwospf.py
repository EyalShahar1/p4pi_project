###############################
#---------- Imports ----------#
###############################

# Used in sniff()
from select import select

# Used for "layers" - common packet headers
from scapy.all import conf, ETH_P_ALL, MTU, plist, Packet, Ether, IP, ARP, sendp

# Used for packets and to bind all the headers into the packet
from scapy.packet import Packet, bind_layers

# Used to parse the different fields in each header in the packet
from scapy.fields import ByteField, LenField, IntField, ShortField, LongField, IntEnumField, PacketListField

# Used for the different threads
from threading import Thread, Event, Lock

# Used by the router controller to distribute packets to different fibers
from queue import Queue

# Used to fetch the current time, in order to keep track of neighbors and topology
from time import time

# Used in the implementation of the djikstra algorithm
import heapq

# Used for creating data plane table entries
import p4runtime_lib.helper

# Used for sending the table entries to the data plane
import p4runtime_lib.switch


#################################
#---------- Constants ----------#
#################################

# Op code of ARP reply
ARP_OP_REPLY = 0x0002

# Op code of ARP request
ARP_OP_REQ = 0x0001

# Timeout for ARP entries
# TODO - use this value to remove entries from ARP table
ARP_TIMEOUT = 30

# The type code of PWOSPF HELLO packets
HELLO_TYPE = 0x01

# The type code of PWOSPF LSU packets
LSU_TYPE = 0x04

# OSPF IP protocol number
OSPF_PROT_NUM = 0x59

# The "ALLSPFRouters" IP address, used to flood HELLO packets
PWOSPF_HELLO_DEST = '224.0.0.5'

# The type code of CPU metadata packets
TYPE_CPU_METADATA = 0x080a

# The broadcast MAC address
BROADCAST_MAC_ADDR = 'ff:ff:ff:ff:ff:ff'

# The Helloint interval for the entire network
HELLOINT_IN_SECS = 10

# The initial HELLO counter value for neighbors
INITIAL_HELLOINT = 3 * HELLOINT_IN_SECS

# The LSUint interval for the entire network
LSUINT_IN_SECS = 30

# The LSU timeout for topology entries
LSU_TIMEOUT = 3 * LSUINT_IN_SECS

# For simplicity, we defined the entire network as one area with the same area ID
AREA_ID = 1

# Invalid sequence number for topology entries (LSUad)
INVALID_SEQUENCE_NUM = 0

# PWOSPF protocol version number
VERSION_NUM = 2


########################################
#---------- Sniff() function ----------#
########################################

# This function "sniffs" the socket for packets
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


#########################################
#---------- Class Definitions ----------#
#########################################

# This class defines a neighbor, which is in reality an interface of another router. The neighbor is defined by an IP
# address (of the interface) and a router ID (of the router this interface belongs to)
class Neighbor:
    def __init__(self, router_id, ip_addr):
        # The router ID of the neighbor
        self.router_id = router_id

        # The IP address of the neighbor
        self.ip_addr = ip_addr

        # A counter for the uptime of the neighbor - it will be removed if it reaches 0
        self.uptime_counter = AtomicCounter(initial = INITIAL_HELLOINT)


# This class defines an interface, which is an abstract entity that defines the connection between a router and one of
# its links. The interface is defined by its IP address, its subnet mask, the interval for sending out HELLO packets to
# all its neighbors (which in actuality is constant for the entire network), and its port number.
class Interface:
    def __init__(self, ip_addr, subnet_mask, helloint, port):
        # The IP address of the interface
        self.ip_addr = ip_addr

        # The subnet mask of the interface
        self.subnet_mask = subnet_mask

        # Interval in seconds between HELLO messages
        self.helloint = helloint

        # The port number associated with this interface
        self.port = port

        # A dictionary of neighbors. Every instance starts with an empty dictionary.
        # TODO - decide if I need to lock this dictionary
        self.neighbors = {}

    # Function for adding a new neighbor to the interface's list
    def add_neighbor(self, neighbor_router_id, neighbor_ip):
        # Create a new neighbor instance and add it to interface's neighbor list
        self.neighbors[neighbor_ip] = Neighbor(neighbor_router_id, neighbor_ip)

    # Function for removing a neighbor from the interface's list
    def remove_neighbor(self, neighbor_ip):
        # Remove the neighbor 
        del self.neighbors[neighbor_ip]


# This class defines a topology router entity, which is essentially an PWOSPF router. The topology router is defined by
# a unique router ID, and the sequence number of the last LSU packet that arrived from this router.
class TopologyRouter():
    def __init__(self, router_id, seq_num):
        # The router ID of this router
        self.router_id = router_id

        # The sequence number of the last LSU packet sent from this router
        self.seq_num = seq_num

        # A counter to track how long it's been since the last LSU packet from this host.
        self.lsu_counter = time()

        # A dictionary of neighbors for this router
        self.neighbors = {}


# This class defines a topology neighbor entity. It is defined by its router ID, the subnet mask of the link it
# describes, and the subnet mask of the link it describes.
class TopologyNeighbor():
    def __init__(self, router_id, subnet, mask):
        # The router ID of this neighbor
        self.router_id = router_id

        # The subnet of the link between this neighbor and the router it's the neighbor of
        self.subnet = subnet

        # The mask of the subnet between this neighbor and the router it's the neighbor of
        self.mask = mask


# This class defines a locked counter that can be safely accessed from multiple threads
class AtomicCounter:
    def __init__(self, initial=0):
        # The initial values of the counter
        self.value = initial

        # The lock used when accessing the counter
        self.lock = Lock()

    # This function decrements the value of the counter by the provided amount    
    def decrement(self, amount = 1):
        # Lock before accessing the counter
        with self.lock:
            # Decrease the value
            self.value -= amount

            # Return the new value of the counter
            return self.value

    # This function sets the value of the counter to the provided new value    
    def set_value(self, new_value):
        # Lock before accessing the counter
        with self.lock:
            # Set the new value
            self.value = new_value

            # Return the newly set value
            return self.value


################################################
#---------- Thread Class Definitions ----------#
################################################

# This class defines a thread that handles incoming ARP packets
class ARPManager(Thread):
    def __init__(self, cntrl):
        # Call the Thread class initializer
        super(ARPManager, self).__init__()

        # The router controller of this router
        self.cntrl = cntrl

        # The thread-safe queue from which this thread consumes packets
        self.pkt_queue = Queue()

    # This function creates and adds an entry to the forwarding table
    def add_forwarding_entry(self, dst_ip_addr, dst_mac_addr):
        # Create the table entry
        table_entry = p4runtime_lib.helper.P4InfoHelper.buildTableEntry(
            table_name = "MyEgress.forwarding_table",
            match_fields = {"meta.next_hop_ip_add": (dst_ip_addr, 32)},
            action_name = "MyEgress.set_dst_and_src_mac",
            action_params = {
                "dst_mac": dst_mac_addr
                }
        )

        # Write entry to table
        p4runtime_lib.switch.SwitchConnection.WriteTableEntry(table_entry)

    # This function define sthe activity of the ARP manager - repeatedly consume packets from queue, and either create
    # a reply or add an entry to the ARP table
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
            # TODO - I assume here that the dst MAC was checked in data plane and this is addressed to me
            elif pkt[ARP].op == ARP_OP_REPLY:

                # Add the new information to the forwarding table
                self.add_forwarding_entry(
                    dst_ip_addr = pkt[ARP].psrc,
                    dst_mac_addr = pkt[ARP].hwsrc
                )


# This class defines a thread that periodically sends out HELLO packets
class HelloPacketSender(Thread):
    def __init__(self, cntrl, helloint):
        # Call the Thread class initializer
        super(HelloPacketSender, self).__init__()
        
        # The router controller of this router
        self.cntrl = cntrl

        # The Helloint interval for this router (we used a constant for the entire network)
        self.helloint = helloint

    # This function defines the activity of the HELLO packet sender - repeatedly sends out HELLO packets out of all
    # interfaces, sleeps for helloint seconds, then removes expired neighbors
    def run(self):
        while True:
            # Iterate over all router interfaces
            for interface in self.cntrl.interfaces:
                # Create the HELLO packet
                hello_pkt = Ether(src = self.cntrl.MAC,
                                  dst = BROADCAST_MAC_ADDR) / IP(
                                      src = interface.ip_addr,
                                      dst = PWOSPF_HELLO_DEST
                                      ) / PWOSPF(type = HELLO_TYPE) / Hello(
                                          mask = interface.subnet_mask,
                                          helloint = interface.helloint
                                          )
                # Send out the pacekt
                self.cntrl.send_packet(hello_pkt)

            # Sleep for the helloint interval
            time.sleep(self.helloint)

            # Iterate over all router interfaces
            for interface in self.cntrl.interfaces:
                # Iterate over all interface neighbors
                for neighbor in interface.neighbors.values():
                    # Decrement the uptime counter of the neighbor
                    new_uptime_value = neighbor.uptime_counter.decrement(HELLOINT_IN_SECS)
                    if new_uptime_value <= 0:
                        # Neighbor has timed out, remove it
                        interface.remove_neighbor(neighbor.ip_addr)
            

# This class defines a thread that handles incoming HELLO packets
class HelloManager(Thread):
    def __init__(self, cntrl):
        # Call the Thread class initializer
        super(HelloManager, self).__init__()

        # The router controller of this router
        self.cntrl = cntrl

        # The thread-safe queue from which this thread consumes packets
        self.pkt_queue = Queue()

    # This function define the activity of the HELLO manager - repeatedly consumes packets from queue and handles them
    def run(self):
        # Create the HELLO packet sender thread
        hello_pkt_sender = HelloPacketSender(self.cntrl, HELLOINT_IN_SECS)
        
        # Start the HELLO packet sender thread
        hello_pkt_sender.start()

        while True:
            # Consume packets from queue
            pkt = self.pkt_queue.get()

            # Iterate over the router's interfaces
            for interface in self.cntrl.interfaces:
                # Find the ingress interface using the ingress port
                if interface.port == pkt[CPUMetadata].ingressPort:
                    # Check if the interface already knows this neighbor
                    neighbor = interface.neighbors.get(pkt[IP].src)
                    if neighbor is not None:
                        # Reset the neighbor's HELLO counter
                        neighbor.uptime_counter.set_value(INITIAL_HELLOINT)

                    else:
                        # If neighbor not found, add it
                        interface.add_neighbor(pkt[PWOSPF]["router ID"], pkt[IP].src)
                    
                    break


# This class defines a thread the periodically sends out LSU packets
class LsuPacketSender(Thread):
    def __init__(self, cntrl, lsuint):
        # Call the Thread class initializer
        super(LsuPacketSender, self).__init__()
        
        # The router controller of this router
        self.cntrl = cntrl

        # The LSUint interval for this router (we used a constant for the entire network)
        self.lsuint = lsuint

    # This function defines the activity of the LSU packet sender - repeatedly sends out LSU packets out of all
    # interfaces then sleeps for LSUint seconds
    def run(self):
        while True:
            # Iterate over the router's interfaces
            for interface in self.cntrl.interfaces:
                # Iterate over the interface's neighbors
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
                # Send out LSU packet
                self.cntrl.send_pkt(lsu_pkt)

            # Sleep for LSUint seconds
            time.sleep(self.lsuint)
        

# This class defines a thread that handles incoming LSU packets
class LSUManager(Thread):
    def __init__(self, cntrl, lsuint):
        # Call the Thread class initializer
        super(LSUManager, self).__init__()

        # The router controller of this router
        self.cntrl = cntrl

        # This router's LSUint (is actually a constant for the entire network)
        self.lsuint = lsuint

        # The thread-safe queue from which this thread consumes packets
        self.pkt_queue = Queue()

        # An adjency list - a dictionary of Topology routers (with the key being the router ID), each holding a
        # dictionary of topology router neighbors (meaning their router ID)
        # TODO - how to initially fill this?
        self.topology = {}

    # This function runs the djikstra algorithm on the network topology, and returns the predecessors - the "next hop"
    # for each router
    def run_djikstra(self):
        # The currently unvisited nodes in the network
        unvisited_nodes = {self.topology.keys()}
        # The predecessors for each node
        predecessors = {key : None for key in self.topology.keys()}
        # A dictionary of all minimal distances for the network nodes
        distances = {key : float('inf') for key in self.topology.keys()}
        # Initialize this router's distance to 0
        distances[self.cntrl.router_id] = 0
        
        # Initialize a heap (queue) of all nodes and their distances
        nodes_heap = [(self.topology[key], key) for key in self.topology.keys()]
        heapq.heapify(nodes_heap)

        # While the queue is not empty
        while nodes_heap:
            # Get the node with the current minimal distance
            current_distance, current_router = heapq.heappop(nodes_heap)
            # Remove the current node from the unvisited nodes set
            unvisited_nodes.remove(current_router)

            # Iterate over the current router's neighbors
            for neighbor in current_router.neighbors:
                # Don't revisit a visited node
                if neighbor.router_id not in unvisited_nodes:
                    continue

                # Check if we found a shorter distance
                if current_distance + 1 < distances[neighbor.router_id]:
                    # Update the neighbor's minimal distance
                    distances[neighbor.router_id] = current_distance + 1
                    # Update the neighbor's distance in the heap
                    # TODO - make sure I don't get duplicates
                    heapq.heappush(nodes_heap, (current_distance + 1, neighbor.router_id))
                    # Update the neighbor's predecessor
                    predecessors[neighbor.router_id] = current_router

        # Return the predecessors of all routers
        return predecessors
    
    # This function creates and adds an entry to the routing table
    def fill_routing_table(self, predecessors):
        # Generate the entry for every IP
        # TODO - handle the case where the predecessor is not a neighbor
        for router_id in predecessors:
            predecessor = predecessors[router_id]

            for interface in self.cntrl.interfaces:
                for neighbor in interface.neighbors:
                    if neighbor.router_id == predecessor:
        
                        # Create the table entry
                        # TODO - get the dst ip address from subnet
                        table_entry = p4runtime_lib.helper.P4InfoHelper.buildTableEntry(
                            table_name = "MyIngress.routing_table",
                            match_fields = {"hdr.ipv4.dstAddr": (dst_ip_addr)},
                            action_name = "MyIngress.ipv4_forward",
                            action_params = {
                                "next_hop": neighbor.ip_addr,
                                "port": interface.port
                                }
                                )

                        # Write entry to table
                        p4runtime_lib.switch.SwitchConnection.WriteTableEntry(table_entry)

    # This function defines the activity of the LSU manager - repeatedly consume packets from queue and handle them
    def run(self):
        # Create the LSU packet sender thread
        lsu_pkt_sender = LsuPacketSender(self.cntrl, self.lsuint)

        # Start the LSU packet sender thread
        lsu_pkt_sender.start()

        while True:
            # Consume packets from queue
            pkt = self.pkt_queue.get()
            should_run_djikstra = False

            # Get the router ID of the sender
            src_router_id = pkt[PWOSPF]["Router ID"]

            # If the packet came from this router - do nothing
            if src_router_id == self.cntrl.routerID:
                continue
            
            # Get the topology router that matches the source router
            src_router = self.topology.get(src_router_id)

            # If the source router is not in this router's database topology
            if src_router is None:
                # Add the source router
                src_router = TopologyNeighbor(src_router_id)
                # Should run djikstra since a new node was added to the topology
                should_run_djikstra = True

            # Get the sequence number of the LSU packet
            curr_seq_num = pkt[LSU].sequence

            # Check if this packet was already received
            if curr_seq_num == src_router.seq_num:
                continue

            # Initialize an empty set for existing topology neighbors for the source router
            found_neighbors_ids = set()

            # Iterate over the LSUads
            # TODO - check for each packet that there's no conflict
            for LSUad in pkt[LSU].LSUads:
                # Get the topology neighbor that matches this LSUad
                topology_neighbor = src_router.neighbors.get(LSUad["router ID"])
                if topology_neighbor is None:
                    # New neighbor, add it
                    src_router.neighbors[LSUad["router ID"]] = TopologyNeighbor(LSUad["router ID"],
                                                                                LSUad["subnet"],
                                                                                LSUad["mask"])
                    # A change was made to the topology, should run djikstra
                    should_run_djikstra = True

                # Add the router ID to the neighbors set
                found_neighbors_ids.add(LSUad["router ID"])
                    
            # Iterate over the source router topology neighbors
            for neighbor in src_router.neighbors.values():
                # If the neighbor was found in the LSU packet
                if neighbor.router_id in found_neighbors_ids:
                    # Reset the neighbor's LSU counter
                    neighbor.lsu_counter = time()
                else:
                    # Neighbor was not included in the LSU packet, check if it's expired
                    if time() - neighbor.lsu_counter > LSU_TIMEOUT:
                        # Neighbor expired, remove it
                        del src_router.neighbors[neighbor]
                        # A change was made to the topology, should run djikstra
                        should_run_djikstra = True

            if should_run_djikstra:
                # Run the djikstra algorithm on the new topology
                predecessors = self.run_djikstra()
                # Fill the routing table with updates entries
                self.fill_routing_table(predecessors)

            # TODO - might need to flood this LSU packet


# This class defines a thread that controlls the router 
class RouterController(Thread):
    def __init__(self, sw, routerID, MAC, areaID, interfaces, lsuint=2, start_wait=0.3):
        # Call the Thread class initializer
        super(RouterController, self).__init__()

        self.sw = sw

        # The router ID of the router
        self.routerID = routerID

        # The MAC address of the router
        self.MAC = MAC

        # The area ID of the router
        self.areaID = areaID

        # List of router interfaces
        self.intfs = interfaces

        # The interval in seconds between link state update broadcasts
        self.lsuint = lsuint

        # Sequence number for outgoing LSU packets
        self.lsu_seq = 0

        self.start_wait = start_wait

        # Stop event for sniffing packets
        self.stop_event = Event()

        # The controller's ARP manager thread
        self.arp_manager = None

        # The controller's HELLO manager thread
        self.hello_manager = None

        # The controller's LSU manager thread
        self.lsu_manager = None

    # This function sends an incoming packet to the appropriate queue
    def process_pkt(self, pkt):
        if ARP in pkt:
            # ARP packet
            self.arp_manager.pkt_queue.put(pkt)
        elif Hello in pkt:
            # HELLO packet
            self.hello_manager.pkt_queue.put(pkt)
        elif LSU in pkt:
            # LSU packet
            self.lsu_manager.pkt_queue.put(pkt)

    # This function sniffs the socket for packets
    def sniff_interface(self):
        # Sniff for packets
        return sniff(store = False, prn = self.process_pkt, stop_event = self.stop_event, refresh = 0.1)
    
    # This function sends a packet to the data plane
    def send_pkt(self, pkt):
        sendp(pkt, iface = self.sw)

    # This function gets an LSU sequence number for a packet
    def get_lsu_seq(self):
        # Increment the sequence number so it's unique
        self.lsu_seq = self.lsu_seq + 1
        # return the sequence number
        return self.lsu_seq
    
    # This function returns the LSUads for outgoing LSU packets
    def get_lsu_ads(self):
        # TODO - implement
        pass

    # This function defines the activity of the router controller - repeatedly sniffs for packets and distributed them
    # to the appropriate thread
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

        # TODO - maybe need to sniff all interfaces
        self.sniff_interface()

        
# CPU metadata header
class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [
        # Packet ingress port
        ShortField("ingressPort", 0)
    ]


# PWOSPF header + payload
class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [
        # Protocol version number
        ByteField("version", VERSION_NUM),
        # Type of PWOSPF packet
        ByteField("type", 0),
        # The length of the packet
        LenField("packet length", 0),
        # The source router ID 
        IntField("router ID", 0),
        # The source area ID
        IntField("area ID", AREA_ID),
        # Checksum
        ShortField("checksum", 0),
        # Authentication type
        ShortField("autype", 0),
        # Authentication
        LongField("authentication", 0)
    ]


# HELLO header + payload
class Hello(PWOSPF):
    name = "Hello"
    fields_desc = [
        # The network mask of the source
        # TODO - might need to be 0xFFFFFFFF, and might need to be IPField
        IntField("network mask", '255.255.255.0'),
        # Helloint interval
        ShortField("HelloInt", HELLOINT_IN_SECS),
        # Padding
        ShortField("padding", 0)
    ]


# LSUad
class LSUad(Packet):
    name = "LSUad"
    fields_desc = [
        # Subnet
        # TODO - maybe IPField?
        IntField("subnet", '0.0.0.0'),
        # Mask
        # maybe IPField?
        IntField("mask", '255.255.255.0'),
        # Router ID
        IntField("router ID", 0)
    ]


# LSU header + payload
class LSU(PWOSPF):
    name = "LSU"
    fields_desc = [
        # Packet sequence number
        IntField("sequence", INVALID_SEQUENCE_NUM),
        # TTL
        IntEnumField("TTL", 0),
        # Number of advertisments
        LongField("advertisements", 0),
        # Advertisments payload
        # TODO - maybe fieldlistfield
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