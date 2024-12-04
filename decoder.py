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

import struct
import socket
from xdrlib import Unpacker

LISTEN_PORT = 53
DNS_SERVER = "8.8.8.8"


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
        41: "OPT",  # EDNS0 option
        43: "DS",  # Delegation Signer
        46: "RRSIG",  # DNSSEC signature
        47: "NSEC",  # Next Secure
        48: "DNSKEY",  # DNS Key Record
        257: "CAA",  # Certification Authority Authorization
        64: "SVCB",  # Service Binding
        65: "HTTPS",  # HTTPS specific record
        256: "URI",  # Uniform Resource Identifier
    }

    return query_type_map.get(qtype, f"{qtype}")


def decode_dns_query(data):
    """Decodes DNS query."""
    header = struct.unpack("!6H", data[:12])  # Les 12 bits du header
    # On extrait une par une les informations
    transaction_id = header[0]
    _flags = header[1]
    qd_count = header[2]  # Nombre de questions
    an_count = header[3]  # Nombre de réponses
    _ns_count = header[4]  # Nombre d'autorités
    _ar_count = header[5]  # Nombre d'additionnels

    index = 12
    qname = []

    # Query part
    while True:
        length = data[index]
        if length == 0:
            break
        try:
             qname.append(data[index + 1: index + 1 + length].decode("utf-8", errors="replace"))
        except UnicodeDecodeError:
            print(f"Invalid domain name character: {data[index + 1 : index + 1 + length]}")
            qname.append("error")
        index += length + 1

    qname = ".".join(qname)
    index += 1  # Skip the null byte at the end of the qname

    qtype, qclass = struct.unpack("!HH", data[index : index + 4])
    index += 4

    assert qclass == 1, f"Expected class 1, got {qclass}"
    assert qd_count == 1, f"Expected 1 question, got {qd_count}"
    assert an_count == 0, f"Expected 0 answers, got {an_count}"
    assert isinstance(qtype, int), f"Expected qtype to be an integer, got {qtype} of type {type(qtype)}"

    data = (qname, qtype, qclass)

    return transaction_id, index, data


# Décode une réponse DNS et retourne un dictionnaire structuré
def decode_dns_response(data, index, query_data, raw_query_data=None):
    """Décode la réponse DNS et retourne un dictionnaire structuré."""
    header = struct.unpack("!6H", data[:12])  # 12 premiers octets de l'en-tête
    an_count = header[3]  # Nombre d'enregistrements de réponse
    ar_count = header[5] # Nombre d'enregistrements additionnels
    rcode = header[1] & 0x0F
    assert an_count > 0, f"Expected at least 1 answer, got {an_count}"


    flags = header[1]
    tc_bit = (flags & 0b00000010) >> 1

    return_list = {
        "answer": an_count,
        "records": [],  # Liste contenant tous les enregistrements
        "query": query_data,  # Les données de la requête
        "rcode": rcode,
        "edns0": ar_count,
        "truncated": tc_bit,
    }

    for _ in range(an_count):
        qname, index = decode_domain_name(data, index)
        # rtype, rclass, ttl, rdlength
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[index : index + 10])
        index += 10
        # Création de la structure pour chaque enregistrement
        record = {
            "qname": qname,
            "class": rclass,
            "type": query_type_to_string(rtype),
            "ttl": ttl,
            "data": None,  # Ce sera rempli selon le type d'enregistrement
        }

        # Gestion des différents types d'enregistrements
        if rtype == 1:  # Enregistrement A (IPv4)
            record["data"] = socket.inet_ntoa(data[index : index + 4])
            index += 4
        elif rtype == 28:  # Enregistrement AAAA (IPv6)
            record["data"] = socket.inet_ntop(socket.AF_INET6, data[index : index + 16])
            index += 16
        elif rtype == 15:  # Enregistrement MX
            preference = struct.unpack("!H", data[index : index + 2])[0]
            index += 2
            exchange = decode_domain_name(data, index)
            record["data"] = f"Préférence={preference}, Échange={exchange}"
            index += rdlength - 2
        elif rtype == 6:  # Enregistrement SOA
            mname, index = decode_domain_name(data, index)
            rname, index = decode_domain_name(data, index)
            record["data"] = f"Primary NS={mname}, Responsible NS={rname}"
            index += 20
        elif rtype == 2:  # Enregistrement NS (Serveur de noms)
            nameserver = decode_domain_name(data, index)
            record["data"] = nameserver
            index += rdlength
        elif rtype == 5:  # Enregistrement CNAME (Nom canonique)
            cname = decode_domain_name(data, index)
            record["data"] = cname[0]
            index += rdlength
        elif rtype == 12:  # Enregistrement PTR (Pointeur)
            ptr = decode_domain_name(data, index)
            record["data"] = ptr[0]
            index += rdlength
        elif rtype == 33:  # Enregistrement SRV (Localisateur de service)
            priority, weight, port = struct.unpack("!HHH", data[index : index + 6])
            index += 6
            target = decode_domain_name(data, index)
            record["data"] = (
                f"Priority={priority}, Weight={weight}, Port={port}, Target={target}"
            )
            index += rdlength - 6
        elif rtype == 65:  # Enregistrement HTTPS spécifique
            index += rdlength
        elif rtype == 16:  # Enregistrement TXT
            txt_data = []
            end = index + rdlength  # Délimite la fin des données TXT
            while index < end:
                # Récupère la longueur du segment TXT
                txt_length = data[index]
                index += 1  # Avance d'un octet (longueur)
                # Extrait le segment de texte
                txt_data.append(data[index: index + txt_length].decode('utf-8', errors='replace'))
                index += txt_length  # Avance selon la longueur du segment
            # Concatène tous les segments dans le champ "data"
            record["data"] = " ".join(txt_data)
        elif rtype == 64:  # Enregistrement SVCB (Service Binding)
            index += 2
            target_name, index = decode_domain_name(data, index)
            record["data"] = target_name
        elif rtype == 256:  # Enregistrement URI
            index += 4
            target = data[index:index + rdlength - 4].decode("utf-8", errors="replace")
            index += len(target)
            record["data"] = target
        else:
            # Gestion des enregistrements inconnus
            record["data"] = (
                f"Type inconnu (Code {rtype}) - Données brutes: {data[index:index + rdlength]}"
            )
            index += rdlength

            # Ajouter l'enregistrement à la liste
        return_list["records"].append(record)
    return return_list



def decode_domain_name(data, index):
    labels = []
    visited_offsets = set()  # Pour détecter les boucles infinies

    while True:
        if index >= len(data):
            raise IndexError(f"Index out of range for data length")

        length = data[index]

        # Pointeur compressé (2 octets)
        if length & 0xC0 == 0xC0:
            if index + 1 >= len(data):
                raise IndexError(f"Pointer index out of range")
            pointer = ((length & 0x3F) << 8) | data[index + 1]
            if pointer in visited_offsets:
                raise ValueError(f"Infinite loop detected in pointer")
            visited_offsets.add(pointer)
            labels.append(decode_domain_name(data, pointer)[0])
            return ".".join(labels), index + 2

        # Fin du nom de domaine
        if length == 0:
            return ".".join(labels), index + 1

        # Longueur invalide (au-delà de 63 octets)
        if length > 63:
            raise ValueError(f"Invalid label length")

        # Lire le label
        index += 1
        if index + length > len(data):
            raise IndexError(f"Label length out of range")
        try:
            labels.append(data[index:index + length].decode("utf-8"))
        except:
            labels.append(data[index:index + length].decode("utf-8", errors="replace"))
        index += length