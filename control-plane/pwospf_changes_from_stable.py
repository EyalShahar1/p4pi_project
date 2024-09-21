#!/usr/bin/env python3

###############################
#---------- Imports ----------#
###############################

# Used for type hints
from __future__ import annotations
from typing import Dict, List

# Used in sniff()
from select import select

# Used for "layers" - common packet headers
from scapy.all import conf, ETH_P_ALL, MTU, PacketList, Packet, Ether, IP, ARP, sendp

# Used for packets and to bind all the headers into the packet
from scapy.packet import Packet, bind_layers

# Used to parse the different fields in each header in the packet
from scapy.fields import ByteField, LenField, IntField, ShortField, LongField, PacketListField, IPField, XShortEnumField

# Used for the different threads
from threading import Thread, Event, Lock, current_thread

# Used by the router controller to distribute packets to different fibers
from queue import Queue

# Used to fetch the current time, in order to keep track of neighbors and topology
from time import time, sleep

# Used in the implementation of the djikstra algorithm
import heapq

# Used for creating data plane table entries
import p4runtime_lib.helper

# Used for sending the table entries to the data plane
import p4runtime_lib.switch

# Used for reading command line arguments
import sys

# Used for getting the subnet mask
import ipaddress

import socket

# Packet queues - global
arp_queue = Queue()
hello_queue = Queue()
lsu_queue = Queue()

# Used for adding multicast group for flooding
# NAAMA TODO - might not be needed
multicast_group_id = 1
egress_ports = [0, 1]

# The p4info helper used to add p4 table entries - global
p4info_helper = p4runtime_lib.helper.P4InfoHelper('/root/bmv2/bin/router.p4info.txt')

#################################
#---------- Constants ----------#
#################################

# Op code of ARP reply
ARP_OP_REPLY = 0x0002

# Op code of ARP request
ARP_OP_REQ = 0x0001

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

# Type code for IPV4 packets
TYPE_IPV4 = 0x0800

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

# Invalid router ID
INVALID_routerID = 0

# The constant and unused authentication type and authentication value for all network routers and packets
AUTHENTICATION_TYPE = 0
AUTHENTICATION_VALUE = 0

# Initial TTL
INITIAL_TTL = 255

# The interface used for communication between the data plane and the control plane
DATA_PLANE_IFACE = "veth0"

# The data plane's forwarding table name
FORWARDING_TABLE_NAME = "MyEgress.forwarding_table"

# The data plane's routing table name
ROUTING_TABLE_NAME = "MyIngress.routing_table"

# Host IP and MAC addresses
HOST_1_IP =  '169.254.1.1'
HOST_1_MAC = 'd8:cb:8a:06:47:70'
HOST_1_SUBNET = '169.254.1.0'
HOST_1_MASK = '255.255.255.0'
HOST_2_IP =  '169.254.2.1'
HOST_2_MAC = '5c:f9:dd:6c:5e:88'
HOST_2_SUBNET = '169.254.2.0'
HOST_2_MASK = '255.255.255.0'

NEED_ARP_REQ = 1


########################################
#---------- Sniff() function ----------#
########################################

# This function "sniffs" the socket for packets
def sniff(store=False, prn=None, lfilter=None, stop_event=None, refresh=.1, *args, **kwargs):
    # Listen for packets
    s = conf.L2listen(type=ETH_P_ALL, iface = DATA_PLANE_IFACE, *args, **kwargs)
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
    return PacketList(lst, "Sniffed")


#########################################
#---------- Class Definitions ----------#
#########################################

# This class defines a neighbor, which is in reality an interface of another router. The neighbor is defined by an IP
# address (of the interface) and a router ID (of the router this interface belongs to)
class Neighbor:
    def __init__(self, routerID : int, ipAddr : str):
        # The router ID of the neighbor
        self.routerID = routerID

        # The IP address of the neighbor
        self.ipAddr = ipAddr

        # A counter for the uptime of the neighbor - it will be removed if it reaches 0
        self.uptimeCounter = AtomicCounter(initial = INITIAL_HELLOINT)


# This class defines a "topology neighbor", which is essentially the contents of an LSUad.
class TopologyNeighbor:
    def __init__(self, routerID : int, subnet : str, mask : str):
        # The router ID of the neighbor router
        self.routerID = routerID

        # The subnet of the link between the neighbor and the RouterNeighbor
        self.subnet = subnet

        # The subnet mask of the link between the neighbor and the RouterNeighbor
        self.mask = mask


# This class defines an interface, which is an abstract entity that defines the connection between a router and one of
# its links. The interface is defined by its IP address, its subnet mask, the interval for sending out HELLO packets to
# all its neighbors (which in actuality is constant for the entire network), and its port number.
class Interface:
    def __init__(self, ipAddr : str, subnetMask : str, helloint : int, port : int, neighbors : Dict[str,Neighbor]):
        # The IP address of the interface
        self.ipAddr = ipAddr

        # The subnet mask of the interface
        self.subnetMask = subnetMask

        # Interval in seconds between HELLO messages
        self.helloint = helloint

        # The port number associated with this interface
        self.port = port

        # A dictionary of neighbors. Every instance starts with an empty dictionary. The key is the IP of the neighbor,
        # and the value is a Neighbor instance.
        # TODO - decide if I need to lock this dictionary
        self.neighbors = {}

    # Function for adding a new neighbor to the interface's list
    def add_neighbor(self, cntrl : RouterController, neighbor_routerID : int, neighbor_ip : str, neighbor_mask : str):
        # Create the neighbor instance for the new neighbor
        new_neighbor = Neighbor(neighbor_routerID, neighbor_ip)
        # Add it to interface's neighbor list
        print("Interface: Adding router", neighbor_routerID, "as neighbor for interface", self.ipAddr)
        self.neighbors[neighbor_ip] = new_neighbor
        # Add this router to the topology
        cntrl.topology.add_router(neighbor_routerID, TopologyRouterInfo())
        # Add to this router's neighbor dictionary in topology
        neighbor_subnet = ipaddress.IPv4Network(neighbor_ip + "/" + neighbor_mask, strict = False)
        neighbor_subnet = neighbor_subnet.network_address
        new_topology_neighbor = TopologyNeighbor(neighbor_routerID, neighbor_subnet, neighbor_mask)
        cntrl.topology.add_neighbor_to_router(cntrl.routerID, new_topology_neighbor)

    # Function for removing a neighbor from the interface's list
    def remove_neighbor(self, cntrl : RouterController, neighbor : Neighbor):
        print("Interface: Removing router", neighbor.routerID, "as neighbor for interface", self.ipAddr)
        # Remove the neighbor from this interface's dictionary
        del self.neighbors[neighbor.ipAddr]
        # Remove neighbor and all its entries from routing table, plus the subnet
        # between this router and the removed neighbor
        topology = cntrl.topology.get()
        removed_router_neighbors = topology[neighbor.routerID].neighbors.values()
        for neighbor in removed_router_neighbors:
            cntrl.delete_entry_routing_table(neighbor.subnet)
        cntrl.delete_entry_routing_table(neighbor.ipAddr)
        # Delete the subnet between this router and the removed router
        removed_neighbor = topology[cntrl.routerID].neighbors[neighbor.routerID]
        cntrl.delete_entry_routing_table[removed_neighbor.subnet]
        cntrl.topology.set(topology)
        # Remove this neighbor from the topology and from this router's topology neighbors
        cntrl.topology.remove_router(neighbor.routerID)
        cntrl.topology.remove_neighbor_from_router(cntrl.routerID, neighbor.routerID)


# This class defines a locked counter that can be safely accessed from multiple threads
class AtomicCounter:
    def __init__(self, initial : int = 0):
        # The initial values of the counter
        self.value = initial

        # The lock used when accessing the counter
        self.lock = Lock()

    # This function decrements the value of the counter by the provided amount
    def decrement(self, amount : int = 1):
        # Lock before accessing the counter
        with self.lock:
            # Decrease the value
            self.value -= amount

        # Return the new value of the counter
        return self.value

    # This function sets the value of the counter to the provided new value
    def set_value(self, new_value : int):
        # Lock before accessing the counter
        with self.lock:
            # Set the new value
            self.value = new_value

        # Return the newly set value
        return self.value

class TopologyRouterInfo:
    def __init__(self):
        self.seq_num = INVALID_SEQUENCE_NUM
        self.last_recv_lsu = time()
        self.neighbors = {}

# This class represents the topology as this router sees it, essentially an
# adjency list of each router and its known neighbors
class Topology:
    def __init__(self, this_routerID : int):
        # A dictionary with router ID as keys, and values of TopologyRouterInfo
        self.topology = {this_routerID : TopologyRouterInfo()}

        # A lock for accessing the topology
        self.topology_lock = Lock()

    # Function for getting the topology
    def get(self) -> Topology:
        with self.topology_lock:
            return self.topology

    # Function for adding a router to the topology
    def add_router(self,
                     new_key : int,
                     new_value : TopologyRouterInfo):
        print("topology: adding router", new_key)
        with self.topology_lock:
            self.topology[new_key] = new_value

    # Function for removing a router from the topology
    def remove_router(self, key_to_remove : int):
        print("topology: removing router", key_to_remove)
        with self.topology_lock:
            del self.topology[key_to_remove]

    # Function for adding a neighbor to a router's neighbors
    def add_neighbor_to_router(self,
                               routerID : int,
                               topology_neighbor : TopologyNeighbor):
        print("topology: adding neighbor", topology_neighbor.routerID, "to router ", routerID)
        with self.topology_lock:
            this_router_neighbors = self.topology[routerID].neighbors
            this_router_neighbors[topology_neighbor.routerID] = topology_neighbor

    # Function for removing a neighbor from a router's neighbors
    def remove_neighbor_from_router(self,
                                    routerID : int,
                                    topology_neighbor_id : int):
        print("topology: removing neighbor", topology_neighbor_id, "from router", routerID)
        with self.topology_lock:
            this_router_neighbors = self.topology[routerID].neighbors
            del this_router_neighbors[topology_neighbor_id]

    def update_router_seq_num_and_uptime(self,
                                         routerID : int,
                                         new_seq_num : int):
        with self.topology_lock:
            self.topology[routerID].seq_num = new_seq_num
            self.topology[routerID].last_recv_lsu = time()


################################################
#---------- Thread Class Definitions ----------#
################################################

# This class defines a thread that handles incoming ARP packets
class ARPManager(Thread):
    def __init__(self, cntrl : RouterController):
        # Call the Thread class initializer
        super(ARPManager, self).__init__()

        # The router controller of this router
        self.cntrl = cntrl

    # This function creates and adds an entry to the forwarding table
    def add_forwarding_entry(self, action : str, dst_ipAddr : str, dst_mac_addr : str= ''):
        # Make sure this entry doesn't already exist in the table
        forwarding_table_id = p4info_helper.get_id("tables", FORWARDING_TABLE_NAME)
        if self.cntrl.entry_already_exists(FORWARDING_TABLE_NAME, forwarding_table_id, dst_ipAddr):
            print("forwarding entry for", dst_ipAddr, "already exists")
            return
        
        # Create the table entry
        if 'no_action' in action:
            print("Adding forwarding entry for IP", dst_ipAddr, "MAC", dst_mac_addr)
            table_entry = p4info_helper.buildTableEntry(
                table_name = FORWARDING_TABLE_NAME,
                match_fields = {"meta.next_hop_ip_add": (dst_ipAddr)},
                action_name = "MyEgress.no_action",
                action_params = {}
            )

        else:
            print("Adding forwarding entry for IP", dst_ipAddr, "MAC", dst_mac_addr)
            table_entry = p4info_helper.buildTableEntry(
                table_name = FORWARDING_TABLE_NAME,
                match_fields = {"meta.next_hop_ip_add": (dst_ipAddr)},
                action_name = action,
                action_params = {
                    "dst_mac": dst_mac_addr
                }
            )

        # Write entry to table
        self.cntrl.switch_connection.WriteTableEntry(table_entry)

    # This function defines the activity of the ARP manager - repeatedly consume packets from queue, and either create
    # a reply or add an entry to the ARP table
    def run(self):
        while True:
            # Consume packets from queue
            pkt = arp_queue.get()

            # Check if packet is an ARP request
            if pkt[ARP].op == ARP_OP_REQ:
                print("ARP manager: got ARP request from", pkt[ARP].psrc)

                # Check if the destination IP matches the interface's IP
                for interface in self.cntrl.interfaces:
                    if pkt[ARP].pdst == interface.ipAddr:
                        # Build ARP reply
                        arp_reply_pkt = Ether(src = self.cntrl.MAC, dst = pkt[Ether].src) / ARP(
                            op = ARP_OP_REPLY,
                            hwsrc = self.cntrl.MAC,
                            psrc = pkt[ARP].pdst,
                            hwdst = pkt[ARP].hwsrc,
                            pdst = pkt[ARP].psrc)

                        # Send out ARP reply
                        print("ARP manager: sending ARP reply for IP", interface.ipAddr)
                        self.cntrl.send_pkt(arp_reply_pkt)

            # Check if packet is an ARP reply
            # TODO - I assume here that the dst MAC was checked in data plane and this is addressed to me
            elif pkt[ARP].op == ARP_OP_REPLY:

                print("ARP manager: got ARP reply")
                # Add the new information to the forwarding table
                self.add_forwarding_entry('MyEgress.set_dst_and_src_mac',
                                          dst_ipAddr = pkt[ARP].psrc,
                                          dst_mac_addr = pkt[ARP].hwsrc
                )

            elif CPUMetadata in pkt and pkt[CPUMetadata].needArpRequest == NEED_ARP_REQ:
                # Generate ARP request
                
                # Find the egress interface
                for interface in self.cntrl.interfaces:
                    if interface.port == pkt[CPUMetadata].egressPort:
                        src_ip = interface.ipAddr

                arp_req_pkt = Ether(src = self.cntrl.MAC, dst = BROADCAST_MAC_ADDR) / ARP(
                            op = ARP_OP_REQ,
                            hwsrc = self.cntrl.MAC,
                            psrc = src_ip,
                            hwdst = BROADCAST_MAC_ADDR,
                            pdst = pkt[IP].dst)
                
                # Send the ARP request
                print("ARP manager: sending ARP request for IP", pkt[IP].dst)
                self.cntrl.send_pkt(arp_req_pkt)



# This class defines a thread that periodically sends out HELLO packets
class HelloPacketSender(Thread):
    def __init__(self, cntrl : RouterController, helloint : int, event : Event):
        # Call the Thread class initializer
        super(HelloPacketSender, self).__init__()

        # The router controller of this router
        self.cntrl = cntrl

        # The Helloint interval for this router (we used a constant for the entire network)
        self.helloint = helloint

        # Event (adding/removing a neighbor) that triggers a LSU
        self.event = event

    # This function defines the activity of the HELLO packet sender - repeatedly sends out HELLO packets out of all
    # interfaces, sleeps for helloint seconds, then removes expired neighbors
    def run(self):
        while True:
            # Iterate over all router interfaces
            for interface in self.cntrl.interfaces:
                # Create the HELLO packet
                hello_pkt = Ether(src = self.cntrl.MAC,
                                  dst = BROADCAST_MAC_ADDR,
                                  type = TYPE_CPU_METADATA) / CPUMetadata(origEtherType = 0x0800, egressPort = interface.port) / IP(
                                      src = interface.ipAddr,
                                      dst = PWOSPF_HELLO_DEST,
                                      proto = OSPF_PROT_NUM
                                      ) / PWOSPF(type = HELLO_TYPE,
                                                 routerId = self.cntrl.routerID) / Hello(networkMask = interface.subnetMask,
                                                                                         HelloInt = interface.helloint)
                # Send out the pacekt
                print("Hello packet sender: sending HELLO packet from", interface.ipAddr, "to port", interface.port)
                self.cntrl.send_pkt(hello_pkt)

            # Sleep for the helloint interval
            sleep(self.helloint)

            # Iterate over all router interfaces
            for interface in self.cntrl.interfaces:
                # Iterate over all interface neighbors
                for neighbor in interface.neighbors.values():
                    # Decrement the uptime counter of the neighbor
                    new_uptime_value = neighbor.uptimeCounter.decrement(self.helloint)
                    if new_uptime_value <= 0:
                        # Neighbor has timed out, remove it and send out LSU about it
                        interface.remove_neighbor(self.cntrl, neighbor)
                        # Set the event to trigger an LSU
                        self.event.set()


# This class defines a thread that handles incoming HELLO packets
class HelloManager(Thread):
    def __init__(self, cntrl : RouterController, event : Event):
        # Call the Thread class initializer
        super(HelloManager, self).__init__()

        # The router controller of this router
        self.cntrl = cntrl

        # Event for triggering an LSU flood
        self.event = event

    # This function define the activity of the HELLO manager - repeatedly consumes packets from queue and handles them
    def run(self):
        # Create the HELLO packet sender thread
        hello_pkt_sender = HelloPacketSender(self.cntrl, HELLOINT_IN_SECS, self.event)

        # Start the HELLO packet sender thread
        print("Hello manager: starting HELLO packet sender")
        hello_pkt_sender.start()

        while True:
            # Consume packets from queue
            pkt = hello_queue.get()
            # Check packet validity
            bIsFromMe = False
            for interface in self.cntrl.interfaces:
                if pkt[IP].src == interface.ipAddr:
                    bIsFromMe = True
                    break

            if bIsFromMe:
                continue

            print("Hello manager: received HELLO pkt from", pkt[IP].src, "from port", pkt[CPUMetadata].ingressPort)
            if self.cntrl.check_pwospf_pkt_validity(pkt) is False:
                print("Hello manager: received invalid HELLO (pwospf) packet")
                # Packet is invalid, drop
                continue

            # Find the ingress interface
            ingress_interface = self.cntrl.get_ingress_interface(pkt)

            if self.cntrl.check_hello_pkt_validity(pkt, ingress_interface) is False:
                print("Hello manager: received invalid HELLO packet")
                # Packet is invalid, drop
                continue

            # Check if the interface already knows this neighbor
            neighbor = ingress_interface.neighbors.get(pkt[IP].src)
            if neighbor is not None:
                print(current_thread().name, "Hello manager: received HELLO packet from known neighbor", pkt[IP].src)
                # Reset the neighbor's HELLO counter
                neighbor.uptimeCounter.set_value(INITIAL_HELLOINT)

            else:
                # If neighbor not found, add it
                ingress_interface.add_neighbor(self.cntrl, pkt[PWOSPF].routerId, pkt[IP].src, pkt[Hello].networkMask)
                self.event.set()


# This class defines a thread the periodically sends out LSU packets
class LsuPacketSender(Thread):
    def __init__(self, cntrl : RouterController, lsuint : int, event : Event):
        # Call the Thread class initializer
        super(LsuPacketSender, self).__init__()

        # The router controller of this router
        self.cntrl = cntrl

        # The LSUint interval for this router (we used a constant for the entire network)
        self.lsuint = lsuint

        # Event to wait on for a change (adding/removing) in neighbors
        self.event = event

    # This function runs the djikstra algorithm on the network topology, calculates the "next hop" predecessors
    # for all subnets, and adds them to the routing table
    def run_djikstra(self)-> Dict[int,int]:
        # Fill a dictionary with the router IDs of all neighbors, and add neighbors to routing table
        neighbor_routers = {}
        for interface in self.cntrl.interfaces:
            for neighbor in interface.neighbors.values():
                neighbor_routers[neighbor.routerID] = (neighbor.ipAddr, interface.port)
                self.cntrl.add_entry_routing_table(neighbor.ipAddr, 32, neighbor.ipAddr, interface.port)

        topology = self.cntrl.topology.get()
        # The currently unvisited nodes in the network
        unvisited_nodes = list(topology.keys())
        # The predecessors for each router (tree)
        router_predecessors = {key: None for key in unvisited_nodes}
        # A dictionary of all minimal distances for the network nodes
        distances = {key : float('inf') for key in unvisited_nodes}
        # Initialize this router's distance to 0
        distances[self.cntrl.routerID] = 0
        # Subnets already added to the routing table
        found_subnets = set()

        # Initialize a heap (queue) of all nodes and their distances
        nodes_heap = []
        for key in distances.keys():
            nodes_heap.append((distances[key], key))
        heapq.heapify(nodes_heap)

        # While the queue is not empty
        while nodes_heap:
            # Get the node with the current minimal distance
            current_distance, current_routerID = heapq.heappop(nodes_heap)
            if current_routerID not in unvisited_nodes:
                # Don't revisit a node
                continue
            # Remove the current node from the unvisited nodes set
            unvisited_nodes.remove(current_routerID)

            # Iterate over the current router's neighbors
            current_router_neighbors = topology[current_routerID].neighbors
            for neighbor_id in current_router_neighbors.keys():
                # Don't revisit a visited node
                if neighbor_id not in unvisited_nodes:
                    continue

                # Check if we found a shorter distance
                new_distance = current_distance + 1
                if new_distance < distances[neighbor_id]:
                    # Update the neighbor's minimal distance
                    distances[neighbor_id] = new_distance
                    # Update the neighbor's distance in the heap
                    # TODO - make sure I don't get duplicates
                    heapq.heappush(nodes_heap, (new_distance, neighbor_id))
                    # Update the router's predecessor
                    router_predecessors[neighbor_id] = current_routerID

            if current_routerID != self.cntrl.routerID:
                # Find the "next hop" for this router's subnets, since the current router is not a neighbor
                next_hop_routerID = router_predecessors.get(current_routerID)
                # Make sure the predecessor of the current router is a neighbor of this router
                while next_hop_routerID not in neighbor_routers.keys():
                        next_hop_routerID = router_predecessors[next_hop_routerID]
            else:
                # The current router is a neighbor, so it is the next hop
                next_hop_routerID = current_routerID

            router_neighbors = topology[current_routerID].neighbors.values()
            for neighbor in router_neighbors:
                if neighbor.subnet not in found_subnets:
                    self.cntrl.add_entry_routing_table(neighbor.subnet,
                                                       24,
                                                       neighbor_routers[next_hop_routerID][0],
                                                       neighbor_routers[next_hop_routerID][1])
                    
    # This function defines the activity of the LSU packet sender - repeatedly sends out LSU packets out of all
    # interfaces then sleeps for LSUint seconds, or until a change in topology occurres (the event is triggered)
    def run(self):
        self.event.clear()
        while True:
            if self.event.is_set:
                # We woke up because of a topology change, run run_djikstra
                print("LSU packet sender: running djikstra")
                self.run_djikstra()
                self.event.clear()

            # Check if there are outdated neighbors in topology
            topology = self.cntrl.topology.get()
            curr_time = time()
            for routerID, router_info in topology.items():
                if routerID == self.cntrl.routerID:
                    continue
                if curr_time - router_info.last_recv_lsu > LSU_TIMEOUT:
                    # Router timed out, remove from topology
                    self.cntrl.topology.remove_router(routerID)

            # Send LSU packets to all neighbors
            curr_seq_num = self.cntrl.get_lsu_seq()
            ads = self.cntrl.get_lsu_ads()
            # Iterate over the router's interfaces
            for interface in self.cntrl.interfaces:
                # Iterate over the interface's neighbors
                for neighbor in interface.neighbors.values():
                    # Create LSU packet
                    lsu_pkt = Ether(src = self.cntrl.MAC,
                                    dst = BROADCAST_MAC_ADDR,
                                    type = TYPE_CPU_METADATA) / CPUMetadata(origEtherType = 0x0800, egressPort = interface.port) / IP(
                                        src = interface.ipAddr,
                                        dst = neighbor.ipAddr,
                                        proto = OSPF_PROT_NUM
                                        ) / PWOSPF(type = LSU_TYPE,
                                                   routerId = self.cntrl.routerID) / LSU(
                                            sequence = curr_seq_num,
                                            numAds = len(ads),
                                            LSUads = ads
                                            )
                    
                    # Send out LSU packet
                    print("LSU packet sender: sending lsu packet from", interface.ipAddr, "to port", interface.port)
                    self.cntrl.send_pkt(lsu_pkt)

            # Sleep for LSUint seconds or until there's a change in topology
            self.event.wait(timeout = self.lsuint)


# This class defines a thread that handles incoming LSU packets
class LSUManager(Thread):
    def __init__(self, cntrl : RouterController, lsuint : int, event : Event):
        # Call the Thread class initializer
        super(LSUManager, self).__init__()

        # The router controller of this router
        self.cntrl = cntrl

        # This router's LSUint (is actually a constant for the entire network)
        self.lsuint = lsuint

        self.event = event

    # This function defines the activity of the LSU manager - repeatedly consume packets from queue and handle them
    def run(self):
        # Create the LSU packet sender thread
        lsu_pkt_sender = LsuPacketSender(self.cntrl, self.lsuint, self.event)

        # Start the LSU packet sender thread
        print("LSU manager: starting LSU packet sender")
        lsu_pkt_sender.start()

        while True:
            # Consume packets from queue
            pkt = lsu_queue.get()

            # Check packet validity
            if self.cntrl.check_pwospf_pkt_validity(pkt) is False:
                # Packet is invalid, drop
                print("LSU manager: invalid lsu packet from", pkt[IP].src)
                continue
            should_run_djikstra = False

            # Get the router ID of the sender
            src_routerID = pkt[PWOSPF].routerId

            # If the packet came from this router - do nothing
            if src_routerID == self.cntrl.routerID:
                continue

            print("LSU manager: got lsu packet from", pkt[IP].src)
            # Get the source router instance (if its existance in the network is known)
            topology = self.cntrl.topology.get()
            router_info = topology.get(src_routerID)
            if router_info is None:
                # First time we hear of this router, add it
                # NAAMA TODO - what about unknown neighbors?
                self.cntrl.topology.add_router(src_routerID, TopologyRouterInfo())
                topology = self.cntrl.topology.get()
                router_info = topology[src_routerID]

            curr_seq_num = router_info.seq_num
            src_router_neighbors = router_info.neighbors

            # Check if this LSU was already received
            if curr_seq_num == pkt[LSU].sequence:
                print("LSU manager: got duplicate LSU packet, dropping")
                continue

            # Initialize an empty set for existing topology neighbors for the source router
            found_neighbors_ids = set()

            # Iterate over the LSUads
            for LSUad in pkt[LSU].LSUads:
                # Get the topology neighbor that matches this LSUad
                topology_neighbor = src_router_neighbors.get(LSUad.routerdID)
                # NAAMA TODO - conflicting updates?
                if topology_neighbor is None:
                    # New neighbor, add it
                    new_neighbor = TopologyNeighbor(LSUad.routerID,
                                                    LSUad.subnet,
                                                    LSUad.mask)
                    self.cntrl.topology.add_neighbor_to_router(src_routerID, new_neighbor)
                    # A change was made to the topology, should run djikstra
                    should_run_djikstra = True

                # Add the router ID to the neighbors set
                found_neighbors_ids.add(LSUad.routerID)

            # Iterate over the source router topology neighbors
            for topology_neighbor in src_router_neighbors.values():
                # If the neighbor was found in the LSU packet
                if topology_neighbor.routerID not in found_neighbors_ids:
                        # Neighbor expired, remove it
                        self.cntrl.topology.remove_neighbor_from_router(src_routerID, topology_neighbor.routerID)
                        # Remove the entry for this subnet from the routing table_entry
                        self.cntrl.delete_entry_routing_table(topology_neighbor.subnet)
                        # A change was made to the topology, should run djikstra
                        should_run_djikstra = True

            # Update sender with new sequence number and uptime
            self.cntrl.topology.update_router_seq_num_and_uptime(src_routerID, pkt[LSU].sequence)

            if should_run_djikstra:
                print("LSU manager: running djikstra")
                # LSU packet sender will run djikstra, fill routing table and send new LSU
                self.event.set()

            # Flood the packet to all neighbors except for incoming interface
            pkt[LSU].TTL = pkt[LSU].TTL - 1
            print("LSU manager: TTL of pkt", pkt[LSU].TTL)
            if pkt[LSU].TTL <= 0:
                continue
            ingress_interface = self.cntrl.get_ingress_interface(pkt)
            for interface in self.cntrl.interfaces:
                if interface.ipAddr == ingress_interface.ipAddr:
                    # Don't flood to ingress interface
                    continue
                pkt[Ether].src = self.cntrl.MAC
                for neighbor in interface.neighbors:
                    pkt[IP].dst = neighbor.ipAddr
                    # Send out LSU packet
                    self.cntrl.send_pkt(pkt)


# This class defines a thread that controlls the router
class RouterController(Thread):
    def __init__(self,
                 sw : str,
                 routerID : int,
                 MAC : str,
                 areaID : int,
                 interfaces : List[Interface],
                 lsuint : int = 2,
                 start_wait : float = 0.3):
        # Call the Thread class initializer
        super(RouterController, self).__init__()

        # TODO - document
        self.sw = sw

        # The router ID of the router
        self.routerID = routerID

        # The MAC address of the router
        self.MAC = MAC

        # The area ID of the router
        self.areaID = areaID

        # List of router interfaces
        self.interfaces = interfaces

        # The interval in seconds between link state update broadcasts
        self.lsuint = lsuint

        # Sequence number for outgoing LSU packets
        self.lsu_seq = 0

        # TODO - document
        self.start_wait = start_wait

        # Stop event for sniffing packets
        self.stop_event = Event()

        # Stop events for topology changes
        self.topology_change_event = Event()

        # The controller's ARP manager thread
        self.arp_manager = ARPManager(self)

        # The controller's HELLO manager thread
        self.hello_manager = HelloManager(self, self.topology_change_event)

        # The controller's LSU manager thread
        self.lsu_manager = LSUManager(self, self.lsuint, self.topology_change_event)

        # An adjency list describing the network topology - a dictionary of
        # routers (key is neighbor (router) ID, value is a tuple of sequence
        # number and a dictionary of TopologyNeighbor instances as values, with
        # router ID keys)
        self.topology = Topology(self.routerID)

        self.switch_connection = None

    def add_entry_routing_table(self, dstAddr : str, prefix_len : int, next_hop : int, port : int):
        # Make sure this entry doesn't already exist in the table
        routing_table_id = p4info_helper.get_id("tables", ROUTING_TABLE_NAME)
        if self.entry_already_exists(ROUTING_TABLE_NAME, routing_table_id, (str(dstAddr), 32)):
            print("routing entry for", dstAddr, "already exists")
            return

        print("Controller: adding entry for addr", dstAddr)
        table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.routing_table",
        match_fields = {"hdr.ipv4.dstAddr": (str(dstAddr), prefix_len)},
        action_name = "MyIngress.ipv4_forward",
        action_params = {
            "next_hop": next_hop,
            "port": port
            }
        )

        # Write entry to table
        self.switch_connection.WriteTableEntry(table_entry)

    def delete_entry_routing_table(self, dstAddr : str):
        print("Controller: deleting entry for addr", dstAddr)
        table_entry = p4info_helper.buildTableEntry(
            table_name = "MyIngress.routing_table",
            match_fields = {"hdr.ipv4.dstAddr": (str(dstAddr) , 32)},
            action_name = None
        )

        # Write entry to table
        self.switch_connection.DeleteTableEntry(table_entry)

    def entry_already_exists(self, table_name, table_id, keys):
        print("checking for keys", keys)
        for readResponse in self.switch_connection.ReadTableEntries(table_id):
            print("checking response")
            for entity in readResponse.entities:
                print("checking entity")
                if entity.HasField('table_entry'):
                    print("entity has table entry")
                    table_entry = entity.table_entry

                    match_key = []
                    match_fields = table_entry.match
                    for field in match_fields:
                        if table_name == FORWARDING_TABLE_NAME:
                            match_key = socket.inet_ntoa(field.exact.value)
                        else:
                            # Routing Table
                            match_key = (socket.inet_ntoa(field.lpm.value), field.lpm.prefix_len)

                    if match_key == keys:
                        return True
                    else:
                        print("read entry for", match_key)
        return False
    
    # This function sends an incoming packet to the appropriate queue
    def process_pkt(self, pkt):
        if ARP in pkt:
            # ARP packet
            arp_queue.put(pkt)
        elif CPUMetadata in pkt and pkt[CPUMetadata].needArpRequest == NEED_ARP_REQ:
            # Need to generate ARP request
            arp_queue.put(pkt)
        elif Hello in pkt:
            # HELLO packet
            hello_queue.put(pkt)
        elif LSU in pkt:
            # LSU packet
            lsu_queue.put(pkt)

    # Getting the ingress interface of a packet
    def get_ingress_interface(self, pkt) -> Interface:
        ingress_port = pkt[CPUMetadata].ingressPort
        for interface in self.interfaces:
            if interface.port == ingress_port:
                return interface

        # No interface matches
        return None

    # This function checks the validity of an incoming PWOSPF packet
    def check_pwospf_pkt_validity(self, pkt) -> bool:
        if pkt[PWOSPF].version != VERSION_NUM:
            return False
        # TODO - check checksum
        if pkt[PWOSPF].areaID != AREA_ID:
            return False
        if pkt[PWOSPF].autype != AUTHENTICATION_TYPE:
            return False
        if pkt[PWOSPF].authentication != AUTHENTICATION_VALUE:
            return False
        # Packet is valid
        return True

    # This function checks the validity of an incoming HELLO packet
    def check_hello_pkt_validity(self, pkt, ingress_interface) -> bool:
        if pkt[Hello].networkMask != ingress_interface.subnetMask:
            return False
        if pkt[Hello].HelloInt != ingress_interface.helloint:
            return False
        return True

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
        ads = []
        my_neighbors = self.topology.get()[self.routerID].neighbors
        for neighbor in my_neighbors.values():
            ads.append(LSUad(subnet = neighbor.subnet,
                             mask = neighbor.mask,
                             routerID = neighbor.routerID))
        return ads

    def print_packet_layers(self, pkt):
        layer = pkt
        while layer:
            layer.show()
            layer = layer.payload

    def init_switch_connection(self):
        self.switch_connection = p4runtime_lib.switch.SwitchConnection(name='s1',
        address=('127.0.0.1:50051'),
        device_id=0)
        self.switch_connection.MasterArbitrationUpdate()
        self.switch_connection.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path="/root/bmv2/bin/router.json")

    def init_tables(self):
        if self.routerID == 1:
            self.add_entry_routing_table(HOST_1_IP, 32, HOST_1_IP, 0)
            self.arp_manager.add_forwarding_entry('MyEgress.set_dst_and_src_mac', HOST_1_IP, HOST_1_MAC)
            self.arp_manager.add_forwarding_entry('MyEgress.set_dst_and_src_mac', "169.254.3.2", "10:00:00:00:00:02")
        if self.routerID == 2:
            self.add_entry_routing_table(HOST_2_IP, 32, HOST_2_IP, 0)
            self.arp_manager.add_forwarding_entry('MyEgress.set_dst_and_src_mac', HOST_2_IP, HOST_2_MAC)
            self.arp_manager.add_forwarding_entry('MyEgress.set_dst_and_src_mac', "169.254.3.1", "10:00:00:00:00:01")

        self.arp_manager.add_forwarding_entry('MyEgress.no_action', PWOSPF_HELLO_DEST)

    def init_topology(self):
        if self.routerID == 1:
            host_neighbor = TopologyNeighbor(0, HOST_1_SUBNET, HOST_1_MASK)
        if self.routerID == 2:
            host_neighbor = TopologyNeighbor(0, HOST_2_SUBNET, HOST_2_MASK)

        self.topology.add_neighbor_to_router(self.routerID, host_neighbor)

    # This function defines the activity of the router controller - repeatedly sniffs for packets and distributed them
    # to the appropriate thread
    def run(self):
        # Init and start grpc switch connection
        self.init_switch_connection()
        print("successfully connected to switch")

        self.init_tables()
        print("Successfully filled tables")

        self.init_topology()

        # Start ARP manager
        print("Controller: Starting ARP manager")
        self.arp_manager.start()

        # Start HELLO manager
        print("Controller: Starting HELLO manager")
        self.hello_manager.start()

        # Start LSU manager
        print("Controller: Starting LSU manager")
        self.lsu_manager.start()

        return sniff(store = False, prn = self.process_pkt, stop_event = self.stop_event, refresh = 0.1)


######################################
#---------- Packet Headers ----------#
######################################

# CPU metadata header
class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [
        XShortEnumField("origEtherType", 0x0800, {0x0800: "IP", 0x0806: "ARP"}),
        # Packet ingress port
        ShortField("ingressPort", 0),
        ShortField("egressPort", 0),
        ByteField("needArpRequest", 0)
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
        LenField("packetLen", 0),
        # The source router ID
        IntField("routerId", 0),
        # The source area ID
        IntField("areaID", AREA_ID),
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
        # TODO - might need to be 0xFFFFFFFF
        IPField("networkMask", "255.255.255.0"),
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
        IPField("subnet", '0.0.0.0'),
        # Mask
        IPField("mask", '255.255.255.0'),
        # Router ID
        IntField("routerID", 0)
    ]


# LSU header + payload
class LSU(PWOSPF):
    name = "LSU"
    fields_desc = [
        # Packet sequence number
        IntField("sequence", INVALID_SEQUENCE_NUM),
        # TTL
        IntField("TTL", INITIAL_TTL),
        # Number of advertisments
        LongField("numAds", 0),
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

    if len(sys.argv) != 2:
        print("wrong number of args", len(sys.argv))
        sys.exit(1)

    if sys.argv[1] == "1":
        print("starting router 1")
        interfaces = [
            Interface(
                ipAddr = "169.254.1.2",
                subnetMask = "255.255.255.0",
                helloint = HELLOINT_IN_SECS,
                port = 0
            ),
            Interface(
                ipAddr = "169.254.3.1",
                subnetMask = "255.255.255.0",
                helloint = HELLOINT_IN_SECS,
                port = 1
            )
        ]
        router_controller = RouterController(
            sw = "veth0",
            routerID = 1,
            MAC = "10:00:00:00:00:01",
            areaID = AREA_ID,
            interfaces = interfaces,
            lsuint = LSUINT_IN_SECS
        )
        router_controller.start()

    elif sys.argv[1] == "2":
        print("starting router 2")
        interfaces = [
            Interface(
                ipAddr = "169.254.2.2",
                subnetMask = "255.255.255.0",
                helloint = HELLOINT_IN_SECS,
                port = 0
            ),
            Interface(
                ipAddr = "169.254.3.2",
                subnetMask = "255.255.255.0",
                helloint = HELLOINT_IN_SECS,
                port = 1
            )
        ]
        router_controller = RouterController(
            sw = "veth0",
            routerID = 2,
            MAC = "10:00:00:00:00:02",
            areaID = AREA_ID,
            interfaces = interfaces,
            lsuint = LSUINT_IN_SECS
        )
        router_controller.start()

    else:
        print("unknown router number", sys.argv[1])
