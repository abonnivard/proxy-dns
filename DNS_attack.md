# Les attaques DDoS sur le DNS : Types et mécanismes

Les attaques par déni de service (DDoS) sur le DNS sont conçues pour perturber la résolution des noms de domaine, un service essentiel à Internet. Ces attaques visent les serveurs DNS pour rendre les sites et services inaccessibles aux utilisateurs. Explorons les principaux types d'attaques DDoS axées sur le DNS.

---

## 1. Attaques par amplification DNS

Les attaques par amplification exploitent la capacité des serveurs DNS ouverts à répondre avec des paquets volumineux à des requêtes de petite taille. Les attaquants usurpent l'adresse IP de leur cible pour la submerger avec des réponses massives.

### Fonctionnement :
- L'attaquant envoie une requête DNS, souvent du type `ANY`, à un serveur DNS ouvert.
- La réponse générée, beaucoup plus grande que la requête initiale, est dirigée vers la cible usurpée.
- Cette amplification surcharge la bande passante et les ressources de la cible.

### Impact :
- Surcharge des ressources réseau de la cible.
- Dégradation ou indisponibilité des services en ligne.


---

## 2. Attaques par sous-domaine aléatoire

Ces attaques exploitent la hiérarchie des noms DNS en générant un flux constant de requêtes pour des sous-domaines inexistants, épuisant ainsi les ressources des serveurs DNS autoritaires.

### Fonctionnement :
- Un botnet génère des requêtes pour des sous-domaines aléatoires (e.g., `abc123.domaine.com`, `xyz456.domaine.com`).
- Les serveurs DNS doivent analyser et tenter de résoudre chaque requête, bien qu'aucune réponse valide ne soit possible.
- Les résolveurs intermédiaires peuvent également être saturés, propageant l'impact de l'attaque.

### Impact :
- Épuisement des ressources CPU et mémoire des serveurs DNS autoritaires.
- Ralentissement général des services DNS.
- Indisponibilité du domaine cible pour les utilisateurs légitimes.


---

## 3. Attaques sur la complexité des résolveurs DNS

Ces attaques visent les résolveurs DNS récursifs en exploitant des vulnérabilités dans leur implémentation ou en envoyant des requêtes nécessitant des calculs complexes.

### Fonctionnement :
- L'attaquant envoie des requêtes malicieuses qui forcent le résolveur à effectuer de multiples recherches en cascade.
- Certaines attaques ciblent des vulnérabilités connues, répertoriées dans les CVE (Common Vulnerabilities and Exposures), pour provoquer des comportements anormaux ou des dénis de service.

### Impact :
- Augmentation drastique de la charge sur les résolveurs récursifs.
- Ralentissement ou interruption des services DNS.
- Effet en cascade sur d'autres services en ligne.

### Exemple d’attaque exploitant une faille DNSSEC :
L’attaque **SigJam** de classe KeyTrap, détaillée dans des études récentes, utilise une vulnérabilité dans la validation des signatures DNSSEC par des résolveurs. Lorsqu’un résolveur reçoit une réponse contenant de multiples signatures invalides **RRSIG**, il est obligé d’essayer chaque signature avant de conclure à un échec.

- **Mécanisme :**
  - L'attaquant configure une zone DNS contenant de nombreuses signatures malveillantes, toutes pointant vers une clé DNSKEY.
  - Une seule requête malveillante peut forcer le résolveur à effectuer des centaines de calculs cryptographiques, saturant ses ressources.

- **Vulnérabilité associée :**
  - **CVE-2023-50387**

### Exemple d'attaque exploitant une faille DNS avec NXNSAttack :

L'attaque **NXNSAttack** exploite le mécanisme de délégation des requêtes DNS dans les serveurs récursifs. Elle tire parti de la manière dont un résolveur suit les instructions fournies par des serveurs DNS autoritaires pour résoudre un nom de domaine, générant ainsi un volume massif de trafic indésirable.


- **Mécanisme :**
  1. **Configuration malveillante** : L'attaquant configure une zone DNS avec des délégations malveillantes. La délégation désigne un ensemble de serveurs de noms inexistants ou contrôlés par l'attaquant (e.g., `ns1.fake-server.com`, `ns2.fake-server.com`, etc.).
  2. **Injection de requête** : L'attaquant envoie une requête pour un sous-domaine dans cette zone (e.g., `malicious.domaine.com`), forçant le résolveur à demander une résolution.
  3. **Délégation excessive** : Le serveur autoritaire malveillant renvoie une réponse contenant une longue liste de serveurs de noms non pertinents ou faux pour déléguer la résolution.
  4. **Amplification** : Le résolveur contacte chaque serveur listé, amplifiant ainsi le trafic réseau avec des requêtes inutiles, ce qui peut submerger les ressources réseau et CPU.

- **Vulnérabilité associée :**
  - **CVE-2020-12667**

---

## Liens utiles

- [Attaques par amplification DNS - Explications et contre-mesures (Cloudflare)](https://www.cloudflare.com/fr-fr/learning/ddos/dns-amplification-ddos-attack/)

- [Attaques par sous domaine aléatoire - Explications](https://www.akamai.com/fr/glossary/what-are-pseudo-random-subdomain-attacks)

- [Attaques sur la compléxité des resolvers DNS - KeyTrap: Vulnérabilité critique dans l'infrastructure Internet](https://www.athene-center.de/keytrap)

- [Attaques sur la complexité des résolveurs DNS - NXNSAttack](https://nvd.nist.gov/vuln/detail/CVE-2020-12667)

- [RFC 8482 - Comment minimiser la réponse d'une requête DNS de type ANY](https://datatracker.ietf.org/doc/html/rfc8482)

- [RFC 4035 - Protocoles pour la validation DNSSEC](https://datatracker.ietf.org/doc/html/rfc4035)


---


