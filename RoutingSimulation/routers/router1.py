import socket
import sys
import time
import os
import glob


# Helper Functions

# The purpose of this function is to set up a socket connection.
def create_socket(host, port):
    # Create a socket.
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Try connecting the socket to the host and port.
    try:
        soc.connect((host, port))
    except:
        print("Connection Error to", port)
        sys.exit()
    # Return the connected socket.
    return soc


# The purpose of this function is to read in a CSV file.
def read_csv(path):
    # Open the file for reading.
    table_file = open(path, "r")
    # Store each line.
    table = table_file.readlines()
    # Create an empty list to store each processed row.
    table_list = []
    # For each line in the file:
    for row in table:
        # Split it by the delimiter and strip
        row = [x.strip() for x in row.split(',')]
        # Append the resulting list to table_list.
        table_list.append(row)
    # Close the file and return table_list.
    table_file.close()
    return table_list


# The purpose of this function is to find the default port
# when no match is found in the forwarding table for a packet's destination IP.
def find_default_gateway(table):
    # Traverse the table, row by row,
    for row in table:
        # If the network destination of that row matches 0.0.0.0,
        if row[0] == "0.0.0.0":
            # Return the interface of that row.
            return row


# The purpose of this function is to generate a forwarding table that includes the IP range for a given interface.
# In other words, this table will help the router answer the question:
# Given this packet's destination IP, which interface (i.e., port) should I send it out on?
def generate_forwarding_table_with_range(table):
    # Create an empty list to store the new forwarding table.
    new_table = []
    # Traverse the old forwarding table, row by row,
    for row in table:
        # Process each network destination other than 0.0.0.0
        # (0.0.0.0 is only useful for finding the default port).
        if row[0] != "0.0.0.0":
            # Store the network destination and netmask.
            network_dst_string = row[0]
            netmask_string = row[1]
            # Convert both strings into their binary representations.
            network_dst_bin = ip_to_bin(network_dst_string)   #''.join(format(ord(i), '08b') for i in network_dst_string)
            netmask_bin = ip_to_bin(netmask_string)    #''.join(format(ord(i), '08b') for i in netmask_string)
            # Find the IP range.
            ip_range = find_ip_range(network_dst_bin, netmask_bin)
            # Build the new row.
            new_row = [ip_range, row[1], row[2], row[3]]
            # Append the new row to new_table.
            new_table.append(new_row)
    # Return new_table.
    return new_table


# The purpose of this function is to convert a string IP to its binary representation.
def ip_to_bin(ip):
    # Split the IP into octets.
    ip_octets = ip.split(".")
    # Create an empty string to store each binary octet.
    ip_bin_string = ""
    # Traverse the IP, octet by octet,
    for octet in ip_octets:
        # Convert the octet to an int,
        int_octet = int(octet)
        # Generate octet ip binary representation
        bin_octet_string = str(format(int_octet, '08b'))
        # Finally, append the octet to ip_bin_string.
        ip_bin_string += bin_octet_string
    # Once the entire string version of the binary IP is created, convert it into an actual binary int.
    ip_bin = bin(int(ip_bin_string, 2))
    # Return the binary representation of this int.
    return ip_bin


# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.
def find_ip_range(network_dst, netmask):
    # Perform a bitwise AND on the network destination and netmask
    # to get the minimum IP address in the range.
    network_dst = int(network_dst, 2)
    netmask = int(netmask, 2)
    bitwise_and = network_dst & netmask
    # Perform a bitwise NOT on the netmask
    # to get the number of total IPs in this range.
    # Because the built-in bitwise NOT or compliment operator (~) works with signed ints,
    # we need to create our own bitwise NOT operator for our unsigned int (a netmask).
    compliment = bit_not(netmask)
    min_ip = bitwise_and
    # Add the total number of IPs to the minimum IP
    # to get the maximum IP address in the range.
    max_ip = compliment | network_dst
    # Return a list containing the minimum and maximum IP in the range.
    return [str(min_ip), str(max_ip)]


# The purpose of this function is to perform a bitwise NOT on an unsigned integer.
def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n


# The purpose of this function is to write packets/payload to file.
def write_to_file(path, packet_to_write, send_to_router=None):
    # Open the output file for appending.
    out_file = open(path, "a")
    # If this router is not sending, then just append the packet to the output file.
    if send_to_router is None:
        out_file.write(packet_to_write + "\n")
    # Else if this router is sending, then append the intended recipient, along with the packet, to the output file.
    else:
        out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
    # Close the output file.
    out_file.close()


# Main Program

# Remove any output files in the output directory
# (this just prevents you from having to manually delete the output files before each run).
files = glob.glob('../output/*')
for f in files:
    os.remove(f)

# Connect to the appropriate sending ports (based on the network topology diagram).
soc_8002 = create_socket("localhost", 8002)
soc_8004 = create_socket("localhost", 8004)

# Read in and store the forwarding table.
forwarding_table = read_csv("../input/router_1_table.csv")
# Store the default gateway port.
default_gateway_port = find_default_gateway(forwarding_table)
# Generate a new forwarding table that includes the IP ranges for matching against destination IPS.
forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

# Read in and store the packets.
packets_table = read_csv("../input/packets.csv")

# For each packet,
for packet in packets_table:
    # Store the source IP, destination IP, payload, and TTL.
    sourceIP = packet[0]
    destinationIP = packet[1]
    payload = packet[2]
    ttl = packet[3]

    # Decrement the TTL by 1 and construct a new packet with the new TTL.
    new_ttl = str(int(ttl) - 1)
    new_packet = sourceIP + ',' + destinationIP + ',' + payload + ',' + new_ttl

    # Convert the destination IP into an integer for comparison purposes.
    destinationIP_bin = ip_to_bin(destinationIP)
    destinationIP_int = int(destinationIP_bin, 2)

    # Find the appropriate sending port to forward this new packet to.
    port = default_gateway_port[3]
    for row in forwarding_table_with_range:
        if int(row[0][0]) <= destinationIP_int <= int(row[0][1]):
            port = row[3]

    # Send the new packet to the appropriate port (and append it to sent_by_router_2.txt),
    # Append the payload to out_router_2.txt without forwarding because this router is the last hop, or
    # Append the new packet to discarded_by_router_2.txt and do not forward the new packet
    if new_ttl == "0" or port == "1":
        print("DISCARD:", new_packet)
        write_to_file("../output/discarded_by_router_1.txt", new_packet)
    elif port == "8002":
        print("sending packet", new_packet, "to Router 2")
        write_to_file("../output/sent_by_router_1.txt", new_packet, "2")
        soc_8002.send(new_packet.encode())
    elif port == "8004":
        print("sending packet", new_packet, "to Router 4")
        write_to_file("../output/sent_by_router_1.txt", new_packet, "4")
        soc_8004.send(new_packet.encode())
    else:
        print("OUT:", payload)
        write_to_file("../output/out_router_1.txt", payload)

    # Sleep for some time before sending the next packet (for debugging purposes)
    time.sleep(1)
