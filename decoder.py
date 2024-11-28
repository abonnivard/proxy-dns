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
        43: "DS",  # Delegation Signer
        46: "RRSIG",  # DNSSEC signature
        47: "NSEC",  # Next Secure
        48: "DNSKEY",  # DNS Key Record
        257: "CAA",  # Certification Authority Authorization
        65: "HTTPS",  # HTTPS specific record
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
def decode_dns_response(data, index, query_data):
    """Décode la réponse DNS et retourne un dictionnaire structuré."""
    header = struct.unpack("!6H", data[:12])  # 12 premiers octets de l'en-tête
    an_count = header[3]  # Nombre d'enregistrements de réponse
    rcode = header[1] & 0x0F
    assert an_count > 0, f"Expected at least 1 answer, got {an_count}"

    flags = header[1]
    tc_bit = (flags & 0b00000010) >> 1
    if tc_bit == 1:
        print("Réponse tronquée détectée. Requête TCP nécessaire : " + str(data))
        return relaunch_query_over_tcp(query_data)


    return_list = {
        "answer": an_count,
        "records": [],  # Liste contenant tous les enregistrements
        "query": query_data,  # Les données de la requête
        "rcode": rcode,

    }

    for _ in range(an_count):
        # Pointeur de nom (2 octets, format compressé)
        name_pointer = struct.unpack("!H", data[index : index + 2])[0]
        index += 2

        qname = decode_domain_name(data, name_pointer & 0x3FFF)

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
            mname = decode_domain_name(data, index)
            index += len(mname) + 1
            rname = decode_domain_name(data, index)
            index += len(rname) + 1
            serial, refresh, retry, expire, minimum = struct.unpack(
                "!IIIII", data[index : index + 20]
            )
            record["data"] = (
                f"MNAME={mname}, RNAME={rname}, SERIAL={serial}, REFRESH={refresh}, RETRY={retry}, EXPIRE={expire}, MINIMUM={minimum}"
            )
            index += 20
        elif rtype == 2:  # Enregistrement NS (Serveur de noms)
            nameserver = decode_domain_name(data, index)
            record["data"] = nameserver
            index += rdlength
        elif rtype == 5:  # Enregistrement CNAME (Nom canonique)
            cname = decode_domain_name(data, index)
            record["data"] = cname
            index += rdlength
        elif rtype == 12:  # Enregistrement PTR (Pointeur)
            ptr = decode_domain_name(data, index)
            record["data"] = ptr
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
            """
            try:
                # Vérifie que l'enregistrement a une longueur suffisante
                if rdlength < 2:
                    raise ValueError(f"Enregistrement HTTPS trop court : rdlength={rdlength}")
                
                print(f"RDATA brut (longueur {rdlength}): {data[index:index + rdlength].hex()}")
                # Extrait la priorité (2 premiers octets)
                priority = struct.unpack("!H", data[index: index + 2])[0]
                index += 2

                # Vérifie si une cible est spécifiée
                if rdlength > 2:
                    # Avant décodage
                    print(f"Position avant TargetName: {index}, Données: {data[index:index + 10].hex()}")

                    # Décodage du TargetName
                    target_name = decode_domain_name(data, index)

                    # Après décodage
                    print(f"TargetName décodé: {target_name}")
                    print(
                        f"Position après TargetName: {index}, Longueur calculée: {len(target_name.encode('utf-8')) + 2}")
                    record["data"] = f"Priority={priority}, Target={target}"
                else:
                    record["data"] = f"Priority={priority}, Target=None"

                # Met à jour l'index selon la longueur de l'enregistrement
                index += rdlength - 2
            except Exception as e:
                record["data"] = f"Erreur de traitement de l'enregistrement HTTPS : {e}"
                index += rdlength
            """
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
    """Helper function to decode compressed domain names in DNS responses."""
    labels = []
    while True:
        length = data[index]

        if length == 0:
            index += 1
            break

        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[index : index + 2])[0]
            pointer &= 0x3FFF
            labels.append(decode_domain_name(data, pointer))
            index += 2
            break

        labels.append(data[index + 1 : index + 1 + length].decode("utf-8"))
        index += length + 1
    return ".".join(labels)


def relaunch_query_over_tcp(query_data):
    """Relance une requête DNS sur TCP en cas de réponse tronquée."""
    try:
        # Création de la socket TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)  # Timeout de 5 secondes pour éviter les blocages
            sock.connect((DNS_SERVER, LISTEN_PORT))

            # Préfixer la requête avec sa longueur (2 octets)
            tcp_query = struct.pack("!H", len(query_data)) + query_data
            sock.sendall(tcp_query)  # Envoi de la requête

            # Lecture de la réponse
            # Les 2 premiers octets indiquent la longueur de la réponse
            response_length_data = sock.recv(2)
            if len(response_length_data) < 2:
                raise ValueError("Impossible de lire la longueur de la réponse.")

            response_length = struct.unpack("!H", response_length_data)[0]
            print(f"Longueur attendue de la réponse : {response_length} octets")

            # Lire la réponse complète
            response = b""
            while len(response) < response_length:
                chunk = sock.recv(response_length - len(response))
                if not chunk:
                    break
                response += chunk

            if len(response) != response_length:
                raise ValueError("Réponse incomplète reçue via TCP.")
            print("Réponse complète reçue via TCP : ", response)
            return response

    except socket.timeout:
        raise TimeoutError("La requête TCP a expiré.")
    except Exception as e:
        raise RuntimeError(f"Erreur lors de la requête TCP : {e}")

