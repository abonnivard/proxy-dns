import os
from datetime import datetime
from elasticsearch import Elasticsearch

ES_HOST = "http://elasticsearch:9200/"

ENVIRONMENT = os.getenv("ENVIRONMENT", "dev")

if ENVIRONMENT == "dev":
    ES_HOST = "http://elasticsearch:9200/"
    es = Elasticsearch([ES_HOST])
else:
    ES_HOST = "http://elasticsearch:9200/"
    ES_USERNAME = os.getenv("ES_USERNAME", "default_user")
    ES_PASSWORD = os.getenv("ES_PASSWORD", "default_password")
    es = Elasticsearch([ES_HOST], basic_auth=(ES_USERNAME, ES_PASSWORD))




def full_log_request(response_data, rcode, source, client_address):
    log_data = {
        "source": source,
        "timestamp": datetime.utcnow(),
        "answers_count": response_data["answer"],
        "rcode": rcode,
        "query_qname": response_data["query"][0],
        "query_type": response_data["query"][1],
        "query_class": response_data["query"][2],
        "client_address": str(client_address),
        "records": [],  # Liste pour contenir les logs détaillés de chaque enregistrement
    }

    # Parcourir les enregistrements et les ajouter à log_data
    for record in response_data["records"]:
        log_data["records"].append(
            {
                "qname": record["qname"],
                "class": record["class"],
                "type": record["type"],
                "ttl": record["ttl"],
                "data": record["data"],
            }
        )

        if response_data.get("edns0"):
            log_data["edns0"] = response_data["edns0"]

    # Indexation dans Elasticsearch
    es.index(index="proxy_logs_full", body=log_data)


def log_request(response_data, rcode, source, client_address):
    """
    Fonction pour logger une requête DNS dans Elasticsearch.
    """
    full_log_request(response_data, rcode, source, client_address)

    log_data = {
        "source": source,
        "timestamp": datetime.utcnow(),
        "answers_count": response_data["answer"],
        "rcode": rcode,
        "query_type": response_data["query"][1],
        "query_class": response_data["query"][2],
        "records": [],  # Liste pour contenir les logs détaillés de chaque enregistrement
    }

    # Parcourir les enregistrements et les ajouter à log_data
    for record in response_data["records"]:
        log_data["records"].append(
            {
                "class": record["class"],
                "type": record["type"],
                "ttl": record["ttl"],
            }
        )

    if response_data.get("edns0"):
        log_data["edns0"] = response_data["edns0"]

    # Indexation dans Elasticsearch
    es.index(index="proxy_logs", body=log_data)


def log_error(error_message, source, query_data_raw, query_data, answer_data, client_address):

    error_message_str = str(error_message)

    if "Expected at least 1 answer, got" not in error_message_str:
        log_data = {
            "timestamp": datetime.utcnow(),
            "type": source,
            "error_message": error_message_str,
            "query_data_raw": query_data_raw,
            "answer_data": answer_data,
            "client_address": str(client_address),
        }

        try:
            log_data["query_qname"] = query_data[0]
        except Exception:
            pass
        try:
            log_data["query_type"] = query_data[1] if str(query_data[1]).isdigit() else None
        except Exception:
            pass
        try:
            log_data["query_class"] = query_data[2]
        except Exception:
            pass

        es.index(index="proxy_errors", body=log_data)


from datetime import datetime
import uuid


def log_suspicious_activity(public_suffix, unique_count, client_address, alert_level="high", additional_info=None):
    """
    Log suspicious activity detected based on unique label count.

    Parameters:
        public_suffix (str): The public suffix of the suspicious activity.
        unique_count (int): The number of unique labels detected under the public suffix.
        client_address (str): The IP address or identifier of the client involved.
        alert_level (str): The severity level of the alert (e.g., 'low', 'medium', 'high').
        additional_info (dict): Additional context or metadata to include in the log.
    """
    # Generate a unique identifier for the log entry
    log_id = str(uuid.uuid4())

    # Build the log data
    log_data = {
        "log_id": log_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "alert_type": "Tunnel DNS suspect",
        "alert_level": alert_level,
        "public_suffix": public_suffix,
        "unique_label_count": unique_count,
        "client_address": client_address,
        "description": (
            f"Suspicious DNS activity detected for {public_suffix}. "
            f"{unique_count} unique subdomains observed from client {client_address}."
        ),
    }

    # Add any additional information if provided
    if additional_info:
        log_data.update({"additional_info": additional_info})

    # Log to Elasticsearch (assuming `es` is your Elasticsearch client)
    es.index(index="suspicious_activity_logs", id=log_id, body=log_data)
