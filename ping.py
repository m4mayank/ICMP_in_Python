import sys
import socket
import struct
import select
import time
import threading
import ipaddress
import self_defined_exceptions

ICMP_CODE = 0
ECHO_REQUEST = 8
ECHO_REPLY=0
DESTINATION_UNREACHABLE = 3
TIME_EXCEEDED = 11

IP_HEADER_FORMAT = "!BBHHHBBHII"
ICMP_HEADER_FORMAT = "!BBHHH"
ICMP_TIME_FORMAT = "!d"


def sum_of_sixteen_bit_words(num1, num2): #one's compliment of 16 bit words
    carry = 1 << 16
    sum = num1 + num2
    return sum if sum < carry else (sum + 1) - carry

def calculate_checksum(data):
    if len(data) % 2:
        data += b'\x00' #if the data elements to be sent are odd then append extra '0' in the end of data
    sum = 0
    for i in range(0, len(data), 2):
        #makes a 16 bit word using 2 alphabets from data at a time
        #example if "mayank" is to be sent the it will be broken down into "am", "ay", "kn", each alphabet uses 8 bit when converted to ascii
        #one of the 8 bit word is shifted and second is added in the remaining 8 bit space to make a 16 bit word
        sum = sum_of_sixteen_bit_words(sum, (data[i + 1] << 8) + data[i])
    return ~sum & 0xffff

def reading_icmp_field_values(byte_data):
    icmp_fields = ('type', 'code', 'checksum', 'id', 'seq')
    #unpacks raw bytes, and puts them in a dictionary corresponding to each item in icmp_fields as the key.
    return dict(zip(icmp_fields, struct.unpack(ICMP_HEADER_FORMAT, byte_data)))

def reading_ip_field_values(byte_data):
    ip_header_keys = ('version', 'tos', 'len', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_addr', 'dest_addr')
    #unpacks raw bytes, and puts them in a dictionary corresponding to each item in icmp_fields as the key.
    ip_header = dict(zip(ip_header_keys, struct.unpack(IP_HEADER_FORMAT, byte_data)))
    ip_header['src_addr'] = str(ipaddress.IPv4Address(ip_header['src_addr']))
    ip_header['dest_addr'] = str(ipaddress.IPv4Address(ip_header['dest_addr']))
    return ip_header

def send_ping(sock, dest_add, icmp_id, seq, size):
    try:
        #if destination is ip then directly used otherwise the name is resolved
        dest_add = socket.gethostbyname(dest_add)
    except socket.gaierror as e:
        print(f"Ping Failed : {e}")
        sys.exit(0)
    #temporary checksum to put in the packet before checksum is calculated on the entire packet
    temp_checksum = 0
    #packing the value of ICMP fields as per the ICMP_HEADER_FORMAT
    icmp_header = struct.pack(ICMP_HEADER_FORMAT, ECHO_REQUEST, ICMP_CODE, temp_checksum, icmp_id, seq)
    ping_string = "root @ Mayank Marwaha#"  #payload string
    #calculating the unsigned char needed for the ping_string and accordingly creating the format
    format_for_string = len(ping_string)*"B"
    extra_padding = (size - struct.calcsize(ICMP_TIME_FORMAT) - struct.calcsize(format_for_string) - struct.calcsize(ICMP_HEADER_FORMAT)) * "/"
    extra_padding = ping_string + extra_padding
    #adding the timestamp on which the ping was sent. This will be used when packet is received to calculate delay.
    icmp_payload = struct.pack(ICMP_TIME_FORMAT, time.time()) + extra_padding.encode()
    final_checksum = calculate_checksum(icmp_header + icmp_payload) #Calculating checksum on the entire packet
    #packing the final checksum into the packet. Htons is to convert data in bytes to network byte order
    icmp_header = struct.pack(ICMP_HEADER_FORMAT, ECHO_REQUEST, ICMP_CODE, socket.htons(final_checksum), icmp_id, seq)
    packet = icmp_header + icmp_payload #putting together the final packet
    sock.sendto(packet, (dest_add, 0))

def receive_ping(sock, icmp_id, seq, timeout, dest):
    #declaring the slice to extract the IP header from received packet
    ip_header_slice = slice(0, struct.calcsize(IP_HEADER_FORMAT))
    #declaring the slice to extract the ICMP header from received packet using the index where IP header ends
    icmp_header_slice = slice(ip_header_slice.stop, ip_header_slice.stop + struct.calcsize(ICMP_HEADER_FORMAT))
    #starting the timeout for receiving ping as per the requirement
    timeout_time = time.time() + timeout
    while True:
        time_left = timeout_time - time.time()
        time_left = time_left if time_left > 0 else 0
        #using the select system call to detect if either of the reading(HERE : socket), writing, exception file descriptor
        #is ready for any kind of I/O operation. It waits until the time_left value mentioned
        selected = select.select([sock, ], [], [], time_left)
        if selected[0] == []: #if no change on socket that means timeout
            raise self_defined_exceptions.Timeout(timeout, dest)    #raising exception to get out of the current ping loop
        time_recv = time.time()
        recv_data, addr = sock.recvfrom(40)
        #extracting the respective headers from the received packet as per the slices declared above
        ip_header_bytes, icmp_header_bytes, payload_bytes = recv_data[ip_header_slice], recv_data[icmp_header_slice], recv_data[icmp_header_slice.stop:]
        ip_header = reading_ip_field_values(ip_header_bytes)
        icmp_header = reading_icmp_field_values(icmp_header_bytes)
        #avoiding the ping from if it does not have the same id with which ping request was sent
        if icmp_header['id'] and icmp_header['id'] != icmp_id:
            continue
        #raising an exception if the response received in response to ping is a TTL expire response
        if icmp_header['type'] == TIME_EXCEEDED and icmp_header['code'] == 0:
                raise self_defined_exceptions.TimeToLiveExpired(dest)
        if icmp_header['id'] and icmp_header['seq'] == seq:
            if icmp_header['type'] == ECHO_REQUEST:
                continue
            if icmp_header['type'] == 0:
                #extracting timestamp from the packet to detect the delay in ping in the end
                time_sent = struct.unpack(ICMP_TIME_FORMAT, payload_bytes[0:struct.calcsize(ICMP_TIME_FORMAT)])[0]
                return time_recv - time_sent



def ping(dest_add, timeout=3, unit= "s", ttl=64, seq= 0, size=56):
    #this function sends one ICMP request and receives back one ICMP reply. Exceptions are put in place to handle the various
    #situations that can arise during a ping cycle
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        icmp_id = threading.current_thread().ident % 0xFFFF #using the current thread as icmp_id
        try:
            send_ping(sock=sock, dest_add=dest_add, icmp_id=icmp_id, seq=seq, size=size)
            delay = receive_ping(sock=sock, icmp_id=icmp_id, seq=seq, timeout=timeout,dest=dest_add)
        except self_defined_exceptions.Timeout as e:
            print(e)
            return "timeout"
        except self_defined_exceptions.TimeToLiveExpired as e:
            print(e)
            return "ttl"
        except self_defined_exceptions.DestinationUnreachable as e:
            print(e)
            return "unreachable"
        except OSError as err:
            print(f"Ping {dest_add}: ",err)
            return("NoRoute")
        except Exception as e:
            print("Unexpected Error during execution! Please enter the correct Destination address")
            sys.exit(0)
        if unit == "ms":
            delay *= 1000
    return delay

def ping_loop(dest_add, count = 4):
    timeout=3
    unit = "ms"
    for i in range(count):
        output_text = f"ping '{dest_add}. . .'"
        delay = ping(dest_add, seq=i,timeout=timeout,unit=unit)
        if delay in ("timeout","ttl","NoRoute"):
            continue
        else:
            print(output_text, end="")
            print("{value}{unit}".format(value=int(delay),unit=unit))
