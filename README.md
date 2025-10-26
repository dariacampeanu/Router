# Main Functionalities

1. **IP Routing Based on a Static Table**
   - Uses a *Longest Prefix Match* algorithm to determine the best route.
   - The table is pre-sorted to allow binary search.

2. **ARP Table Management**
   - Packets that cannot be sent directly due to missing ARP entries are placed in a queue.
   - ARP Requests are sent to resolve the MAC address.
   - When an ARP Reply is received, the ARP table is updated and queued packets are transmitted.

3. **Handling ARP Packets**
   - Upon receiving an ARP Request, an ARP Reply is constructed and sent.
   - Upon receiving an ARP Reply, the ARP table is updated and the waiting queue is cleared.

4. **ICMP**
   - Sends ICMP packets of the following types:
     - Echo Reply (response to ping)
     - Time Exceeded (TTL decreased to 0)
     - Destination Unreachable (when no route to destination exists)
   - ICMP packets are manually constructed, including header formatting and checksum computation.

5. **Destination MAC Verification**
   - Packets are processed only if addressed to the router’s MAC address or are of broadcast type.

---

# Code Structure

- **main()**: Initializes the router, loads the routing table, and enters the main processing loop.  
- **route_comparator()**: Comparator used to sort the routing table by mask and prefix.  
- **longest_prefix_match()**: Function that applies the binary search algorithm to find the best route.  
- **get_arp_entry()**: Searches for an existing ARP entry by IP address.  
- **process_arp_request()** and **process_arp_reply()**: Handle ARP packets.  
- **enqueue_packet_for_arp()**: Queues a packet that cannot be sent due to a missing ARP entry.  
- **try_forward_packet()**: Attempts to retransmit an IP packet to its destination using the proper route and ARP entry.  
- **handle_icmp_echo_reply()**: Builds and sends an ICMP Echo Reply in response to a ping.  
- **build_icmp_error_packet()**: Constructs ICMP error packets (used by `send_icmp_error_packet()`).  
- **buffer_t**: Custom dynamic queue structure used for storing packets waiting for ARP resolution.  

---

# ICMP Packet Construction

ICMP packets are manually generated and include:

- **Ethernet Header** (with source and destination MAC addresses swapped)  
- **IP Header** (with source and destination addresses swapped, TTL reset, checksum recalculated)  
- **ICMP Header** (with the specified type and error code, plus the original payload)
