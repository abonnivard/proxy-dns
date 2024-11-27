import socket

def send_dns_query_tcp(server_ip, port, query):
    """
    Envoie une requête DNS sur le port TCP 53 et affiche la réponse.

    :param server_ip: Adresse IP du serveur DNS.
    :param port: Port du serveur DNS (par défaut 53).
    :param query: Requête DNS binaire.
    """
    try:
        # Création d'un socket TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_ip, port))

            # Envoi de la requête avec la longueur (2 octets) en tête
            sock.sendall(len(query).to_bytes(2, byteorder="big") + query)

            # Réception de la réponse
            response_length = int.from_bytes(sock.recv(2), byteorder="big")
            response = sock.recv(response_length)

            print(f"Réponse reçue : {response.hex()}")
            return response
    except Exception as e:
        print(f"Erreur lors de l'envoi de la requête DNS : {e}")

if __name__ == "__main__":
    # Exemple de requête DNS pour "example.com"
    dns_query = bytes.fromhex(
        "abcd"  # ID (transaction ID)
        "0100"  # Flags (standard query)
        "0001"  # Questions: 1
        "0000"  # Answer RRs: 0
        "0000"  # Authority RRs: 0
        "0000"  # Additional RRs: 0
        "076578616d706c6503636f6d00"  # QNAME: example.com
        "0001"  # QTYPE: A
        "0001"  # QCLASS: IN
    )

    # Adresse IP du serveur DNS
    dns_server = "159.65.55.92"  # Changez pour l'IP de votre serveur DNS

    # Port du serveur DNS
    dns_port = 53

    # Envoi de la requête DNS
    send_dns_query_tcp(dns_server, dns_port, dns_query)
