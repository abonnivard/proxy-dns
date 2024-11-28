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




def full_log_request(response_data, rcode, source):
    log_data = {
        "source": source,
        "timestamp": datetime.utcnow(),
        "answers_count": response_data["answer"],
        "rcode": rcode,
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

    # Indexation dans Elasticsearch
    es.index(index="proxy_logs_full", body=log_data)


def log_request(response_data, rcode, source):
    """
    Fonction pour logger une requête DNS dans Elasticsearch.
    """
    full_log_request(response_data, rcode, source)

    log_data = {
        "source": source,
        "timestamp": datetime.utcnow(),
        "answers_count": response_data["answer"],
        "rcode": rcode,
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

    # Indexation dans Elasticsearch
    es.index(index="proxy_logs", body=log_data)


def log_error(error_message, source, query_data_raw, query_data, answer_data):

    error_message_str = str(error_message)

    if "Expected 0 answers, got" not in error_message_str:
        log_data = {
            "timestamp": datetime.utcnow(),
            "type": source,
            "error_message": str(error_message),
            "query_data_raw": query_data_raw,
            "answer_data": answer_data,
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
