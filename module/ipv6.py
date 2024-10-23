"""Module pour compter le nombre d'IP v6"""

import re
from elasticsearch import Elasticsearch
from datetime import datetime

ES_HOST = "http://localhost:9200"
es = Elasticsearch([ES_HOST])


def update_ipv6_counter(index="ipv6_counter"):
    """Updates the counter for IPv6 requests in the Elasticsearch database."""
    # Query to get the current counter value
    try:
        response = es.get(index=index, id="ipv6_count")
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

    es.index(index=index, id="ipv6_count", body=data)
    print(f"IPv6 request count updated to: {count}")

def log_ipv6_request(ip, index="ipv6_logs"):
    """Logs an IPv6 request and updates the counter if the IP is IPv6."""

    # Si on veut garder des logs des requêtes IPv6
    """data = {
        "ip": ip,
        "query_type": "AAAA",
        "timestamp": datetime.now().isoformat(timespec='milliseconds')
    }
    es.index(index=index, id="ipv6_logs", body=data)"""

    # Update the counter
    update_ipv6_counter()
    print(f"Logged IPv6 request for IP: {ip}")
