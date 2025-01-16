from collections import defaultdict
import time
from publicsuffixlist import PublicSuffixList


# Fenêtre de temps en secondes (par exemple, 10 secondes)
WINDOW_SIZE = 30

# Stockage des statistiques par domaine dans une fenêtre temporelle
dns_stats = defaultdict(lambda: {"count": 0, "unique_subdomains": set()})


# Charger une liste des suffixes publics
psl = PublicSuffixList()


def extract_subdomain(domain):
    """
    Extrait le sous-domaine principal d'un domaine complet sans utiliser de module externe.
    """
    if not domain or not isinstance(domain, str):
        return None  # Domaine invalide

    # Diviser le domaine en parties
    parts = domain.split(".")
    if len(parts) < 2:
        return None  # Pas de domaine valide (par exemple "localhost" ou vide)

    # Identifier le domaine de base (dernier et avant-dernier segments)
    base_domain = ".".join(parts[-2:])

    # Extraire le sous-domaine
    subdomain = ".".join(parts[:-2])  # Tout ce qui précède le domaine de base
    return subdomain if subdomain else None


# Fonction pour nettoyer les fenêtres expirées
def cleanup_expired_windows():
    current_time = time.time()
    expired_keys = [key for key, value in dns_stats.items() if current_time - value["timestamp"] > WINDOW_SIZE]
    for key in expired_keys:
        del dns_stats[key]

# Fonction pour extraire la clé de fenêtre temporelle
def get_window_key(domain):
    current_time = time.time()
    window_start = int(current_time // WINDOW_SIZE) * WINDOW_SIZE
    return (domain, window_start)

# Détection avec fenêtres glissantes
def detect_anomalies(domain, query_type):
    global dns_stats

    if isinstance(domain, bytes):
        domain = domain.decode("utf-8")

    # Nettoyage des anciennes fenêtres
    cleanup_expired_windows()

    # Calculer la clé temporelle
    key = get_window_key(domain)
    if key not in dns_stats:
        dns_stats[key] = {"count": 0, "unique_subdomains": set(), "timestamp": time.time()}

    subdomain = extract_subdomain(domain)
    dns_stats[key]["count"] += 1
    dns_stats[key]["unique_subdomains"].add(subdomain)

    print(f"Statistiques pour {domain} dans la fenêtre {key}: {dns_stats[key]}")

    # Critères pour lever une alerte dans la fenêtre
    if len(dns_stats[key]["unique_subdomains"]) > 50:  # Beaucoup de sous-domaines uniques
        print(f"[ALERTE] Tunnel DNS suspect pour {domain}: >50 sous-domaines uniques détectés dans la fenêtre")
    if any(len(sub) > 63 for sub in dns_stats[key]["unique_subdomains"]):  # Sous-domaine trop long
        print(f"[ALERTE] Tunnel DNS suspect pour {domain}: sous-domaine trop long détecté")
    if dns_stats[key]["count"] > 100 and query_type in ["TXT", "CNAME"]:  # Volume élevé avec type suspect
        print(f"[ALERTE] Tunnel DNS suspect pour {domain}: >100 requêtes de type {query_type} dans la fenêtre")
