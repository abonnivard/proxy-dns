from datetime import datetime
from elasticsearch import Elasticsearch

ES_HOST = "http://elasticsearch:9200/"
es = Elasticsearch([ES_HOST])


def full_log_request(response_data):
    log_data = {
        "timestamp": datetime.utcnow(),
        "answers_count": response_data["answer"],
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
    print("Logged full request to Elasticsearch:", log_data)


def log_request(response_data):
    """
    Fonction pour logger une requête DNS dans Elasticsearch.
    """
    full_log_request(response_data)

    log_data = {
        "timestamp": datetime.utcnow(),
        "answers_count": response_data["answer"],
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
    print("Logged full request to Elasticsearch:", log_data)


def log_error(error_message, source, data):
    log_data = {
        "timestamp": datetime.utcnow(),
        "type": source,
        "error_message": str(error_message),
        "data": data,
    }
    es.index(index="proxy_errors", body=log_data)
    print("Logged error to Elasticsearch:", log_data)
