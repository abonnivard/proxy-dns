from collections import defaultdict
import time
from logger import log_suspicious_activity

# Fenêtre de temps en secondes
WINDOW_SIZE = 60
last_logged_subdomains = {}  # Stocke le dernier seuil enregistré pour chaque domaine

# Stockage des statistiques par domaine parent
dns_stats = defaultdict(lambda: {"count": 0, "unique_subdomains": set(), "timestamp": 0})


def validate_domain(domain):
    """
    Valide qu'un domaine est bien formé (contient au moins un point).
    """
    return domain and '.' in domain


def extract_parent_domain(domain):
    """
    Extrait le domaine parent (par exemple, tunnel.bonnivard.net) d'un domaine complet.
    """
    if not validate_domain(domain):
        return None

    parts = domain.split(".")
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])  # Dernier et avant-dernier segments


def extract_subdomain(domain):
    """
    Extrait le sous-domaine d'un domaine complet (tout ce qui précède le domaine parent).
    """
    if not validate_domain(domain):
        return None

    parts = domain.split(".")
    if len(parts) < 3:
        return None  # Pas de sous-domaine
    return ".".join(parts[:-2])  # Tout sauf les deux derniers segments


def cleanup_expired_windows():
    """
    Supprime les données des fenêtres temporelles expirées.
    """
    current_time = time.time()
    expired_keys = [key for key, value in dns_stats.items() if current_time - value["timestamp"] > WINDOW_SIZE]
    for key in expired_keys:
        del dns_stats[key]


def get_window_key(domain):
    """
    Génère une clé unique pour une fenêtre temporelle donnée.
    """
    current_time = time.time()
    window_start = int(current_time // WINDOW_SIZE) * WINDOW_SIZE
    return (domain, window_start)


def detect_anomalies(domain, query_type, client_address):
    """
    Détecte les anomalies DNS basées sur les statistiques globales regroupées par domaine parent.
    """
    global dns_stats

    if isinstance(domain, bytes):
        domain = domain.decode("utf-8")

    if not validate_domain(domain):
        print(f"[INFO] Domaine invalide ou local ignoré : {domain}")
        return

    # Nettoyage des anciennes fenêtres
    cleanup_expired_windows()

    # Extraire le domaine parent et le sous-domaine
    parent_domain = extract_parent_domain(domain)
    subdomain = extract_subdomain(domain)

    if not parent_domain:
        print(f"[INFO] Impossible d'extraire le domaine parent pour {domain}")
        return

    # Calculer la clé temporelle
    key = get_window_key(parent_domain)
    if key not in dns_stats:
        dns_stats[key] = {"count": 0, "unique_subdomains": set(), "timestamp": time.time()}

    # Mettre à jour les statistiques
    if subdomain:  # Ne pas ajouter None
        dns_stats[key]["unique_subdomains"].add(subdomain)
    dns_stats[key]["count"] += 1

    # Critères pour lever une alerte
    alert_interval = 50  # Intervalle d'alerte pour les sous-domaines uniques

    # Alerte basée sur le nombre élevé de sous-domaines uniques
    unique_subdomain_count = len(dns_stats[key]["unique_subdomains"])
    if unique_subdomain_count > 50:  # Seuil initial de 50
        # Dernier seuil enregistré pour ce domaine
        last_threshold = last_logged_subdomains.get(parent_domain, 0)

        # Vérifier si un nouveau seuil est atteint
        if unique_subdomain_count >= last_threshold + alert_interval:

            # Log dans Elasticsearch
            log_suspicious_activity(
                public_suffix=parent_domain,
                unique_count=unique_subdomain_count,
                client_address=client_address,
                alert_level="high",
                additional_info={
                    "alert_reason": "High number of unique subdomains",
                    "query_count": dns_stats[key]["count"],
                    "query_type": query_type
                }
            )

            # Mettre à jour le dernier seuil logué
            last_logged_subdomains[parent_domain] = unique_subdomain_count

    # Alerte basée sur un volume élevé de requêtes avec un type suspect
    if dns_stats[key]["count"] > 100 and query_type in ["TXT", "CNAME"]:  # Volume élevé avec type suspect

        # Log dans Elasticsearch
        log_suspicious_activity(
            public_suffix=parent_domain,
            unique_count=len(dns_stats[key]["unique_subdomains"]),
            client_address=client_address,
            alert_level="medium",
            additional_info={
                "alert_reason": f"High query volume for type {query_type}",
                "query_count": dns_stats[key]["count"],
                "unique_subdomains_count": len(dns_stats[key]["unique_subdomains"]),
                "query_type": query_type
            }
        )

