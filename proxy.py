import socket
import threading
from decoder import decode_dns_query, decode_dns_response
from logger import log_request

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53
DNS_SERVER = "8.8.8.8"  # Google DNS
DNS_PORT = 53

# UDP socket (datagram method)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_HOST, LISTEN_PORT))

print(f"DNS Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")


def forward_to_resolver(data):
    """Forwards the DNS query to the real DNS resolver."""
    resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver_socket.sendto(data, (DNS_SERVER, DNS_PORT))
    response, _ = resolver_socket.recvfrom(512)
    resolver_socket.close()
    return response


def handle_dns_request(data, addr):
    """Handles the DNS request, forwards it, decodes it, logs it, and sends back the response."""
    try:
        # Decode the query
        transaction_id, question_end_index, query_data = decode_dns_query(data)
        # Forward the request to the real DNS resolver
        response = forward_to_resolver(data)

        # Decode and get the response details
        response_data = decode_dns_response(response, question_end_index, query_data)

        # Log the request
        try:
            log_request(response_data)
        except:
            pass

        # Send the response back to the original client
        sock.sendto(response, addr)
    except Exception as e:
        print(f"Error handling request from {addr}: {e}")


# Main loop to handle incoming DNS requests
while True:
    data, addr = sock.recvfrom(512)
    client_thread = threading.Thread(target=handle_dns_request, args=(data, addr))
    client_thread.start()
