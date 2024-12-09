from elasticsearch import Elasticsearch
import os
import ast
from proxy import forward_to_resolver

def replay_error(error_id, es_host="http://localhost:9200/"):
    """
    Rejoue une requête DNS depuis les erreurs enregistrées dans Elasticsearch.
    :param error_id: ID de l'erreur à rejouer.
    :param es_host: Adresse du serveur Elasticsearch.
    """
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

    try:
        # Récupérer l'erreur par son ID
        error = es.get(index="proxy_errors", id=error_id)["_source"]
        query_data_raw = error.get("query_data_raw")
        # Débogage : vérifier le type de query_data_raw

        print(type(query_data_raw))
        print(query_data_raw)
        query_data_raw = ast.literal_eval(query_data_raw)

        # Rejouer la requête en utilisant forward_to_resolver
        response = forward_to_resolver(query_data_raw, use_tcp=False)
        print(f"Réponse reçue : {response}")
        return response
    except Exception as e:
        print(f"Erreur lors du rejouage : {e}")

# Exécuter depuis la ligne de commande
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage : python replay.py <ID_ERREUR>")
    else:
        replay_error(sys.argv[1])