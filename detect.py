from collections import defaultdict
import time

# Fenêtre de temps en secondes (par exemple, 30 secondes)
WINDOW_SIZE = 30

# Stockage des statistiques par domaine dans une fenêtre temporelle
dns_stats = defaultdict(lambda: {"count": 0, "unique_subdomains": set(), "timestamp": 0})


def validate_domain(domain):
    """
    Valide qu'un domaine est bien formé (contient au moins un point).
    """
    if not domain or not isinstance(domain, str):
        return False
    return '.' in domain


def extract_subdomain(domain):
    """
    Extrait le sous-domaine principal d'un domaine complet sans utiliser de module externe.
    """
    if not validate_domain(domain):
        return None

    parts = domain.split(".")
    if len(parts) < 2:
        return None

    # Identifier le domaine de base (dernier et avant-dernier segments)
    base_domain = ".".join(parts[-2:])

    # Extraire le sous-domaine
    subdomain = ".".join(parts[:-2])  # Tout ce qui précède le domaine de base
    return subdomain if subdomain else None


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
    Détecte les anomalies DNS basées sur les fenêtres temporelles et les statistiques.
    """
    global dns_stats

    if isinstance(domain, bytes):
        domain = domain.decode("utf-8")

    if not validate_domain(domain):
        print(f"[INFO] Domaine invalide ou local ignoré : {domain}")
        return

    # Nettoyage des anciennes fenêtres
    cleanup_expired_windows()

    # Calculer la clé temporelle
    key = get_window_key(domain)
    if key not in dns_stats:
        dns_stats[key] = {"count": 0, "unique_subdomains": set(), "timestamp": time.time()}

    subdomain = extract_subdomain(domain)
    if subdomain:  # Ne pas ajouter None
        dns_stats[key]["unique_subdomains"].add(subdomain)
    dns_stats[key]["count"] += 1

    print(f"Statistiques pour {domain} dans la fenêtre {key}: {dns_stats[key]}")
    print("key:", key)

    # Critères pour lever une alerte dans la fenêtre
    if len(dns_stats[key]["unique_subdomains"]) > 50:  # Beaucoup de sous-domaines uniques
        print(f"[ALERTE] Tunnel DNS suspect pour {domain}: >50 sous-domaines uniques détectés dans la fenêtre")
    if any(len(sub) > 63 for sub in dns_stats[key]["unique_subdomains"]):  # Sous-domaine trop long
        print(f"[ALERTE] Tunnel DNS suspect pour {domain}: sous-domaine trop long détecté")
    if dns_stats[key]["count"] > 100 and query_type in ["TXT", "CNAME"]:  # Volume élevé avec type suspect
        print(f"[ALERTE] Tunnel DNS suspect pour {domain}: >100 requêtes de type {query_type} dans la fenêtre")

