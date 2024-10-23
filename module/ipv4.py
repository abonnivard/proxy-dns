"""Module pour compter le nombre d'IP v4"""

import re
from elasticsearch import Elasticsearch
from datetime import datetime

ES_HOST = "http://localhost:9200"
es = Elasticsearch([ES_HOST])


def update_ipv4_counter(index="ipv4_counter"):
    """Updates the counter for IPv4 requests in the Elasticsearch database."""
    # Query to get the current counter value
    try:
        response = es.get(index=index, id="ipv4_count")
        count = response['_source'].get('count', 0)
    except Exception as e:
        # If the document doesn't exist, initialize the counter
        print(f"Initializing counter: {e}")
        count = 0

    # Increment the counter
    count += 1

    # Update the counter in Elasticsearch
    data = {
        "count": count
    }

    es.index(index=index, id="ipv4_count", body=data)
    print(f"IPv4 request count updated to: {count}")

def log_ipv4_request(ip, index="ipv4_logs"):
    """Logs an IPv4 request and updates the counter if the IP is IPv4."""

    # Si on veut garder des logs des requêtes IPv4
    """data = {
        "ip": ip,
        "query_type": "A",
        "timestamp": datetime.now().isoformat(timespec='milliseconds')
    }
    es.index(index=index, id="ipv4_logs", body=data)"""

    # Update the counter
    update_ipv4_counter()
    print(f"Logged IPv4 request for IP: {ip}")
