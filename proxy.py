import socket
import threading
from decoder import decode_dns_query, decode_dns_response
from logger import log_request, log_error
from detect import detect_anomalies
from collections import defaultdict

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53
DNS_SERVER = "8.8.8.8"  # Google DNS
DNS_PORT = 53
BUFFER_SIZE = 4096



def forward_to_resolver(data, use_tcp=False):
    """Forward the DNS query to the real DNS resolver over UDP or TCP."""
    if use_tcp:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as resolver_socket:
            resolver_socket.connect((DNS_SERVER, DNS_PORT))
            resolver_socket.sendall(len(data).to_bytes(2, byteorder="big") + data)
            response_length = int.from_bytes(resolver_socket.recv(2), byteorder="big")
            response = resolver_socket.recv(response_length)
            return response
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver_socket:
            resolver_socket.sendto(data, (DNS_SERVER, DNS_PORT))
            response, _ = resolver_socket.recvfrom(BUFFER_SIZE)
            return response


def handle_dns_request_udp(sock, data, addr):
    """Handles a DNS request over UDP."""
    client_ip, client_port = addr
    try:
        _transaction_id, question_end_index, query_data, error = decode_dns_query(data)
        detect_anomalies(query_data[2], query_data[1])
        if error:
            raise Exception(error)
        try:
            response = forward_to_resolver(data, use_tcp=False)
            rcode = response[3] & 0x0F  # Récupère le rcode des flags

            response_data = decode_dns_response(
                response, question_end_index, query_data, data
            )


            # Vérification du rcode et des réponses attendues
            if rcode == 3:  # NXDOMAIN
                assert response_data["answer"] == 0, "NXDOMAIN mais des réponses détectées"

            if query_data[0] == 'error':
                log_error(
                    "Invalid qname decode query",
                    source=f"UDP",
                    query_data=query_data,
                    answer_data=str(response),
                    query_data_raw=str(data),
                    client_address=client_ip
                )
            else:
                log_request(response_data, rcode, source="UDP", client_address=client_ip)
            sock.sendto(response, addr)
        except Exception as e:
            if 'response' in locals():
                sock.sendto(response, addr)
            log_error(
                e,
                source=f"UDP",
                query_data=query_data,
                answer_data=str(response) if 'response' in locals() else "No response data",
                query_data_raw=str(data),
                client_address=client_ip
            )
    except Exception as e:
        response = forward_to_resolver(data, use_tcp=False)
        sock.sendto(response, addr)
        log_error(
            e,
            source=f"UDP",
            query_data=query_data if 'query_data' in locals() else None,
            answer_data=str(response),
            query_data_raw=str(data),
            client_address=client_ip
        )


def handle_dns_request_tcp(client_socket, client_addr):
    """Handles a DNS request over TCP."""
    print("TCP request in progress with client : ", client_addr)
    client_ip, client_port = client_addr
    try:
        message_length = int.from_bytes(client_socket.recv(2), byteorder="big")
        data = client_socket.recv(message_length)
        _transaction_id, question_end_index, query_data, error = decode_dns_query(data)
        detect_anomalies(query_data[2], query_data[1])
        if error:
            raise Exception(error)
        try:

            response = forward_to_resolver(data, use_tcp=True)
            response_data = decode_dns_response(
                response, question_end_index, query_data, data
            )
            rcode = response[3] & 0x0F  # Récupère le rcode des flags

            log_request(response_data, rcode, source="TCP", client_address=client_ip)
            client_socket.sendall(len(response).to_bytes(2, byteorder="big") + response)
        except Exception as e:
            if 'response' in locals():
                client_socket.sendall(len(response).to_bytes(2, byteorder="big") + response)
            log_error(
                e,
                source="TCP",
                query_data=query_data,
                answer_data=str(response) if 'response' in locals() else "No response data",
                query_data_raw=str(data),
                client_address=client_ip
            )
    except Exception as e:
        if 'data' in locals():
            response = forward_to_resolver(data, use_tcp=True)
            client_socket.sendall(len(response).to_bytes(2, byteorder="big") + response)
        log_error(e,
                  source="TCP",
                  query_data_raw=str(data) if 'data' in locals() else "No query data",
                  query_data=query_data if 'query_data' in locals() else None,
                  answer_data=str(response) if 'response' in locals() else "No response data",
                  client_address=client_ip
                  )
    finally:
        client_socket.close()


def start_udp_server():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((LISTEN_HOST, LISTEN_PORT))
    print(f"DNS Proxy listening on UDP {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        data, addr = udp_sock.recvfrom(BUFFER_SIZE)
        threading.Thread(
            target=handle_dns_request_udp, args=(udp_sock, data, addr)
        ).start()


def start_tcp_server():
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((LISTEN_HOST, LISTEN_PORT))
    tcp_sock.listen(5)
    print(f"DNS Proxy listening on TCP {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        try:
            client_socket, addr = tcp_sock.accept()
            threading.Thread(target=handle_dns_request_tcp, args=(client_socket,addr)).start()
        except Exception as e:
            print(f"TCP loop exception : {e}")



def main():
    udp_thread = threading.Thread(target=start_udp_server)
    tcp_thread = threading.Thread(target=start_tcp_server)
    udp_thread.start()
    tcp_thread.start()
    udp_thread.join()
    tcp_thread.join()


if __name__ == "__main__":
    main()
