from collections import defaultdict
import time

# Fenêtre de temps en secondes
WINDOW_SIZE = 30

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


def detect_anomalies(domain, query_type):
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

    # Logs des statistiques actuelles
    print(f"Statistiques pour {parent_domain} dans la fenêtre {key}: {dns_stats[key]}")
    print("key", key)

    # Critères pour lever une alerte
    if len(dns_stats[key]["unique_subdomains"]) > 50:  # Nombre élevé de sous-domaines uniques
        print(f"[ALERTE] Tunnel DNS suspect pour {parent_domain}: >50 sous-domaines uniques détectés dans la fenêtre")
    if dns_stats[key]["count"] > 100 and query_type in ["TXT", "CNAME"]:  # Volume élevé avec type suspect
        print(f"[ALERTE] Tunnel DNS suspect pour {parent_domain}: >100 requêtes de type {query_type} dans la fenêtre")
