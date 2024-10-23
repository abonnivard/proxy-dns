import struct
import socket

"""
Header: 12 bytes

ID: 2 bytes (identifies the query)
Flags: 2 bytes (operation code, response flags)
Question Count: 2 bytes (number of questions)
Answer Count: 2 bytes (number of answer records, usually 0 for a query)
Authority Count: 2 bytes (number of authority records)
Additional Count: 2 bytes (number of additional records)
Question Section:

Query Name: Variable-length (name of the domain being queried, encoded as labels)
Query Type: 2 bytes (type of the DNS query, e.g., A, AAAA)
Query Class: 2 bytes (typically 1 for IN, Internet)
(Optional) Answer Section:

This section appears in responses and contains the resolved data.
"""


def query_type_to_string(qtype):
    """Maps a DNS query type number to its corresponding string representation."""
    query_type_map = {
        1: "A",  # IPv4 address
        2: "NS",  # Name Server
        5: "CNAME",  # Canonical Name
        6: "SOA",  # Start of Authority
        12: "PTR",  # Pointer Record
        15: "MX",  # Mail Exchange
        16: "TXT",  # Text Record
        28: "AAAA",  # IPv6 address
        33: "SRV",  # Service locator
        43: "DS",  # Delegation Signer
        46: "RRSIG",  # DNSSEC signature
        47: "NSEC",  # Next Secure
        48: "DNSKEY",  # DNS Key Record
        257: "CAA",  # Certification Authority Authorization
    }

    return query_type_map.get(qtype, f"Unknown query type: {qtype}")


def decode_dns_query(data):
    """Decodes DNS query."""
    header = struct.unpack('!6H', data[:12]) #Les 12 bits du header
    # On extrait une par une les informations
    transaction_id = header[0]
    flags = header[1]
    qd_count = header[2] #Nombre de questions
    an_count = header[3] #Nombre de réponses
    ns_count = header[4] #Nombre d'autorités
    ar_count = header[5] #Nombre d'additionnels


    index = 12
    qname = []

    #Query part
    while True:
        length = data[index]
        if length == 0:
            break
        qname.append(data[index + 1: index + 1 + length].decode('utf-8'))
        index += length + 1

    qname = '.'.join(qname)
    index += 1  # Skip the null byte at the end of the qname

    qtype, qclass = struct.unpack('!HH', data[index:index + 4])
    index += 4

    assert qclass == 1, f"Expected class 1, got {qclass}"
    assert qd_count == 1, f"Expected 1 question, got {qd_count}"
    assert an_count == 0, f"Expected 0 answers, got {an_count}"

    data = (qname, qtype, qclass)

    return transaction_id, index, data


def decode_dns_response(data, index, query_data):
    """Decodes DNS response and returns a structured dictionary."""

    header = struct.unpack('!6H', data[:12])  # First 12 bytes of the header
    an_count = header[3]  # Number of answer records
    return_list = {
        "answer": an_count,
        "records": []  # Liste qui contiendra tous les enregistrements
    }

    for _ in range(an_count):
        # Name pointer (2 bytes, compressed format)
        name_pointer = struct.unpack('!H', data[index:index + 2])[0]
        index += 2

        qname = decode_domain_name(data, name_pointer & 0x3FFF)

        # rtype, rclass, ttl, rdlength
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[index:index + 10])
        index += 10

        # Création de la structure pour chaque enregistrement
        record = {
            "qname": qname,
            "class": rclass,
            "type": query_type_to_string(rtype),
            "ttl": ttl,
            "data": None  # Ce sera rempli selon le type de l'enregistrement
        }

        # Handle different record types
        if rtype == 1:  # A record (IPv4)
            record['data'] = socket.inet_ntoa(data[index:index + 4])
            index += 4
        elif rtype == 28:  # AAAA record (IPv6)
            record['data'] = socket.inet_ntop(socket.AF_INET6, data[index:index + 16])
            index += 16
        elif rtype == 15:  # MX record
            preference = struct.unpack('!H', data[index:index + 2])[0]
            index += 2
            exchange = decode_domain_name(data, index)
            record['data'] = f"Preference={preference}, Exchange={exchange}"
            index += rdlength - 2
        elif rtype == 6:  # SOA record
            mname = decode_domain_name(data, index)
            index += len(mname) + 1
            rname = decode_domain_name(data, index)
            index += len(rname) + 1
            serial, refresh, retry, expire, minimum = struct.unpack('!IIIII', data[index:index + 20])
            record['data'] = f"MNAME={mname}, RNAME={rname}, SERIAL={serial}, REFRESH={refresh}, RETRY={retry}, EXPIRE={expire}, MINIMUM={minimum}"
            index += 20
        else:
            record['data'] = "Unsupported Record Type"
            index += rdlength

        # Ajouter l'enregistrement à la liste
        return_list["records"].append(record)

    return return_list

def decode_domain_name(data, index):
    """Helper function to decode compressed domain names in DNS responses."""
    labels = []
    while True:
        length = data[index]
        if length == 0:
            index += 1
            break
        elif length & 0xC0 == 0xC0:
            pointer = struct.unpack('!H', data[index:index + 2])[0]
            pointer &= 0x3FFF
            labels.append(decode_domain_name(data, pointer))
            index += 2
            break
        else:
            labels.append(data[index + 1:index + 1 + length].decode('utf-8'))
            index += length + 1
    return '.'.join(labels)


"""
Example: www.example.com
-> 03 77 77 77 07 65 78 61 6D 70 6C 65 03 63 6F 6D 00

03: Length of the first label, www
77 77 77: The label "www"
07: Length of the second label, example
65 78 61 6D 70 6C 65: The label "example"
03: Length of the third label, com
63 6F 6D: The label "com"
00: End of the domain name
"""



