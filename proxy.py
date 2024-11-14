import socket
import threading
from decoder import decode_dns_query, decode_dns_response
from logger import log_request, log_error

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
    try:
        _transaction_id, question_end_index, query_data = decode_dns_query(data)
        try:
            response = forward_to_resolver(data, use_tcp=False)
            response_data = decode_dns_response(response, question_end_index, query_data)

            log_request(response_data)
            sock.sendto(response, addr)
        except Exception as e:
            print(f"Error handling UDP request from {addr}: {e}")
            log_error(e, source=f"UDP request from {addr}", data=data, query_data=query_data)
    except Exception as e:
        print(f"Error handling UDP request from {addr}: {e}")
        log_error(e, source=f"UDP request from {addr}", data=data, query_data="no query data")


def handle_dns_request_tcp(client_socket):
    """Handles a DNS request over TCP."""
    try:
        message_length = int.from_bytes(client_socket.recv(2), byteorder="big")
        data = client_socket.recv(message_length)
        _transaction_id, question_end_index, query_data = decode_dns_query(data)
        try:
            response = forward_to_resolver(data, use_tcp=True)
            response_data = decode_dns_response(response, question_end_index, query_data)

            log_request(response_data)
            client_socket.sendall(len(response).to_bytes(2, byteorder="big") + response)
        except Exception as e:
            print(f"Error handling TCP request: {e}")
            log_error(e, source="TCP request",  data=data, query_data=query_data)
    except Exception as e:
        print(f"Error handling TCP request: {e}")
        log_error(e, source="TCP request", data="no data", query_data="no query data")
    finally:
        client_socket.close()


def start_udp_server():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((LISTEN_HOST, LISTEN_PORT))
    print(f"DNS Proxy listening on UDP {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        data, addr = udp_sock.recvfrom(BUFFER_SIZE)
        threading.Thread(target=handle_dns_request_udp, args=(udp_sock, data, addr)).start()


def start_tcp_server():
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((LISTEN_HOST, LISTEN_PORT))
    tcp_sock.listen(5)
    print(f"DNS Proxy listening on TCP {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        client_socket, addr = tcp_sock.accept()
        threading.Thread(target=handle_dns_request_tcp, args=(client_socket,)).start()


def main():
    udp_thread = threading.Thread(target=start_udp_server)
    tcp_thread = threading.Thread(target=start_tcp_server)
    udp_thread.start()
    tcp_thread.start()
    udp_thread.join()
    tcp_thread.join()


if __name__ == "__main__":
    main()
