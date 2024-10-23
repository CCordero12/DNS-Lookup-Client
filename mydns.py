import sys
from socket import socket, AF_INET, SOCK_DGRAM

# create DNS query message
def create_query(id, domain_name):
    # Query header [RFC 4.1.1. Header section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                      ID                       |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    QDCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ANCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    NSCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ARCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    first_row = (id).to_bytes(2, byteorder='big')
    #Most of the fields in the second row do not apply to sending a query.
    #QR is set to 0 to specify a query.
    #RD can be set to 1 if you want a recursive response from the server.
    #Everything else isn't used for a query.
    second_row = (0).to_bytes(2, byteorder='big')
    #Specifies the number of entries in our question section (just 1)
    qdcount = (1).to_bytes(2, byteorder='big')
    #Number of resource records in the answer section 
    ancount = (0).to_bytes(2, byteorder='big')
    nscount = (0).to_bytes(2, byteorder='big')
    arcount = (0).to_bytes(2, byteorder='big')
    header = first_row + second_row + qdcount + ancount + nscount + arcount

    # Question section [RFC 4.1.2. Question section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                                               |
    # /                     QNAME                     /
    # /                                               /
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QTYPE                     |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QCLASS                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    # initialize qname as empty bytes
    qname = b''

    # split domain name into labels
    labels = domain_name.split('.')
    for label in labels:
        qname += len(label).to_bytes(1, byteorder='big')  # length byte
        qname += bytes(label, 'utf-8')  # label bytes
    # zero length byte as end of qname
    qname += (0).to_bytes(1, byteorder='big')

    #Specifies type of query, specified by the type ID, which for type A is 1
    #A Records map the hostname to the corresponding IPv4 address
    qtype = (1).to_bytes(2, byteorder='big')
    #Specifies class of query
    qclass = (1).to_bytes(2, byteorder='big')
    question = qname + qtype + qclass

    #print("Header: ")
    #print(header)
    #print("Question: ") 
    #print(question)
    return header + question

# parse byte_length bytes from index as unsigned integer, return number and index of next byte
def parse_unsigned_int(index, byte_length, response):
    num = int.from_bytes(
        response[index: index + byte_length], byteorder="big", signed=False)
    return num, index + byte_length

# parse name as label serie from index, return name and index of next byte
def parse_name(index, response):
    name = ''
    end = 0
    loop = True
    while loop:
        # end of label serie
        if response[index] == 0:
            loop = False
            if end == 0:
                end = index + 1
        # pointer
        elif response[index] >= int('11000000', 2):
            end = index + 2
            index = int.from_bytes(
                response[index: index + 2], byteorder="big", signed=False) - int('1100000000000000', 2)
        # label
        else:
            label_length = response[index]
            index += 1
            label = response[index: index + label_length].decode('utf-8')
            name += label
            index += label_length
            if response[index] != 0:
                name += '.'

    return name, end

def parse_ip(index, byte_len, response):
    ip_num = ''
    for i in range(0, byte_len):
        ip_num += str(int.from_bytes(response[index + i: index + i + 1], byteorder="big", signed=False))
        #num, throwaway = parse_unsigned_int(index + i, 1, response)
        #ip_num += str(num)
        ip_num += '.'
    ip_num = ip_num[:-1]
    return ip_num, index + byte_len


# response is the raw binary response received from server
def parse_response(response):
    #print('----- parse response -----')
    print("Reply received. Content overview: ")

    # dns message format [RFC 4.1. Format]
    # This example will only parse header and question sections.
    #
    # +---------------------+
    # |        Header       |
    # +---------------------+
    # |       Question      | the question for the name server
    # +---------------------+
    # |        Answer       | RRs answering the question
    # +---------------------+
    # |      Authority      | RRs pointing toward an authority
    # +---------------------+
    # |      Additional     | RRs holding additional information
    # +---------------------+

    # current byte index
    index = 0

    #print('Header section [RFC 4.1.1. Header section format]')
    # Header section [RFC 4.1.1. Header section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                      ID                       |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    QDCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ANCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    NSCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ARCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    num, index = parse_unsigned_int(index, 2, response)
    #print(f'\tID: {num}')

    # skip the next 2 bytes, i.e., second row
    index += 2

    num, index = parse_unsigned_int(index, 2, response)
    #print(f'\tQDCOUNT: {num}')

    #Specifies number of RRs in answer section
    ANCOUNT, index = parse_unsigned_int(index, 2, response)
    print(f'\t{ANCOUNT} Answers.')
    #print(f'\tANCOUNT: {ANCOUNT}')

    #Number of name server RRs in authority records section
    NSCOUNT, index = parse_unsigned_int(index, 2, response)
    print(f'\t{NSCOUNT} Intermediate Name Servers.')
    #print(f'\tNSCOUNT: {NSCOUNT}')

    #Number of RRs in the additional records section
    ARCOUNT, index = parse_unsigned_int(index, 2, response)
    print(f'\t{ARCOUNT} Additional Information Records.')
    #print(f'\tARCOUNT: {ARCOUNT}')


    print('Question section [RFC 4.1.2. Question section format]')
    # Question section [RFC 4.1.2. Question section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                                               |
    # /                     QNAME                     /
    # /                                               /
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QTYPE                     |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QCLASS                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    name, index = parse_name(index, response)
    #print(f'\tQNAME: {name}')

    num, index = parse_unsigned_int(index, 2, response)
    #print(f'\tQTYPE: {num}')

    num, index = parse_unsigned_int(index, 2, response)
    #print(f'\tQCLASS: {num}')

    #TODO: Parse Resource Records 
    #print('Resource Record Section [RFC 4.1.3. Resource record format]')
    #                                1  1  1  1  1  1
    #  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #|                                               |
    #/                                               /
    #/                      NAME                     /
    #|                                               |
    #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #|                      TYPE                     |
    #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #|                     CLASS                     |
    #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #|                      TTL                      |
    #|                                               |
    #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #|                   RDLENGTH                    |
    #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    #/                     RDATA                     /
    #/                                               /
    #+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    

    #Answers Section of the resource records
    if ANCOUNT > 0:
        print("Answers Section: ")
    for i in range(0, ANCOUNT):
        b4_index = index

        name, index = parse_name(index, response)
        #print(f'\tNAME: {name}')

        index = b4_index + 2

        rr_type, index = parse_unsigned_int(index, 2, response)
        #print(f'\tTYPE: {rr_type}')

        num, index = parse_unsigned_int(index, 2, response)
        #print(f'\tCLASS: {num}')

        num, index = parse_unsigned_int(index, 4, response)
        #print(f'\tTTL: {num}')

        rd_len, index = parse_unsigned_int(index, 2, response)
        #print(f'\tRDLENGTH: {rd_len}')
        
        if(rr_type != 1):
            index += rd_len
            print("\t*Non-IPv4 Address Skipped*")
            continue

        IPnum, index = parse_ip(index, rd_len, response)
        #print(f'\tRDATA: {IPnum}')
        print(f'\tName : {name}\tIP : {IPnum}')

    
    #Authority Section of the resource records
    if NSCOUNT > 0:
        print('Authority Section: ')
    for i in range(0, NSCOUNT):
        name, index = parse_name(index, response)
        #print(f'NAME: {name}')

        num, index = parse_unsigned_int(index, 2, response)
        #print(f'TYPE: {num}')

        num, index = parse_unsigned_int(index, 2, response)
        #print(f'CLASS: {num}')

        num, index = parse_unsigned_int(index, 4, response)
        #print(f'TTL: {num}')

        num, index = parse_unsigned_int(index, 2, response)
        #print(f'RDLENGTH: {num}')

        nameserver, index = parse_name(index, response)
        #print(f'RDATA: {nameserver}')
        print(f'\tName : {name}\tName Server : {nameserver}')


    #Additional Section of the resource records
    firstIP = ''
    ip_grabbed = False
    if ARCOUNT > 0:
        print("Additional Information Section: ")
    for i in range(0, ARCOUNT):
        b4_index = index

        name, index = parse_name(index, response)
        #print(f'\tNAME: {name}')

        index = b4_index + 2

        rr_type, index = parse_unsigned_int(index, 2, response)
        #print(f'\tTYPE: {rr_type}')

        num, index = parse_unsigned_int(index, 2, response)
        #print(f'\tCLASS: {num}')

        num, index = parse_unsigned_int(index, 4, response)
        #print(f'\tTTL: {num}')

        rd_len, index = parse_unsigned_int(index, 2, response)
        #print(f'\tRDLENGTH: {rd_len}')
        
        if(rr_type != 1):
            index += rd_len
            print("\t*Non-IPv4 Address Skipped*")
            continue

        IPnum, index = parse_ip(index, rd_len, response)
        #print(f'\tRDATA: {IPnum}')
        print(f'\tName : {name}\tIP : {IPnum}')

        #Grabs the first IP address from the additional section, only used if ANCOUNT == 0
        if not ip_grabbed:
            firstIP = IPnum
            ip_grabbed = True
    
    return firstIP, ANCOUNT




    


    

# get domain-name and root-dns-ip from command line
if len(sys.argv) != 3:
    print('Usage: mydns domain-name root-dns-ip')
    sys.exit()
domain_name = sys.argv[1]
root_dns_ip = sys.argv[2]

print("----------------------------------------------------------------")
print("DNS server to query: " + root_dns_ip)

# create UDP socket
socket = socket(AF_INET, SOCK_DGRAM)

# send DNS query
id = 1
query = create_query(id, domain_name)
socket.sendto(query, (root_dns_ip, 53))
response, server_address = socket.recvfrom(2048)


# parse DNS response
next_ip, answers = parse_response(response)
while(answers == 0):
    print("----------------------------------------------------------------")
    print("DNS server to query: " + next_ip)
    id += 1
    query = create_query(id, domain_name)
    socket.sendto(query, (next_ip, 53))
    response, server_address = socket.recvfrom(2048)
    next_ip, answers = parse_response(response)
#print(response)
exit
