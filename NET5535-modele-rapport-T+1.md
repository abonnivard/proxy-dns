
---

# Rapport de projet à T+1 mois sur le montage d'une plateforme DNS pour recueillir des statistiques réelles de manière respectueuse de la confidentialité
**Auteurs**: Adrien Bonnivard et Jeremy Louis

---

## Contexte

Dans le cadre de notre projet, nous analysons les comportements et caractéristiques des requêtes DNS en utilisant un proxy DNS. Ce projet s'inscrit dans un contexte de sécurité réseau, où l'objectif est d'examiner comment certains types de comportements malveillants, tels que les tunnels DNS et les attaques de déni de service, peuvent être détectés par l’interception et l’analyse de ces requêtes. La configuration d’un proxy DNS permet une inspection en temps réel, tout en intégrant des mesures pour respecter la confidentialité des données.

## Objectifs

Les objectifs de ce projet sont les suivants :
- Développer un proxy DNS capable de capturer et de traiter les requêtes DNS sans journaliser les domaines, sauf en cas de détection de comportements suspects.
- Identifier et surveiller des indicateurs de compromission (IoC) dans le flux DNS, en mettant en place des métriques permettant de détecter des activités inhabituelles comme des sous-domaines dynamiques ou une forte concentration de requêtes similaires.
- Adapter les traitements afin de minimiser les faux positifs (par exemple, pour des domaines comme ceux de Google ou Cloudflare) et les faux négatifs liés à des structures de noms de domaine non conventionnelles.

## Tâches et organisation du projet

Voici les étapes accomplies jusqu’à présent ainsi que les tâches à venir :

- **Configuration initiale du proxy DNS** : Implémentation d'un serveur proxy DNS en python capable de décoder les requêtes et réponses DNS, et de transmettre les requêtes aux résolveurs publics.
- **Développement d’un système de détection de modèles DNS suspects** :
  - Création de scripts pour identifier des motifs de requêtes inhabituels, par exemple un grand nombre de sous-domaines aléatoires sous un même suffixe public (e.g., `truc-aléatoire.domaine.com`).
  - Compteur pour le nombre de valeurs uniques de sous-domaines observés pour chaque suffixe public (par exemple, `x.domaine.com` pour `domaine.com`).
- **Optimisation pour la confidentialité** : Implémentation d’une logique de journalisation conditionnelle, où les requêtes ne sont journalisées que lorsqu’un comportement suspect est identifié.
  
**Prochaines tâches** :
- **Mise en place d’un environnement de test** :
   - Installation du proxy DNS sur une machine virtuelle pour simuler un environnement réaliste et permettre des tests en conditions réelles.
   - Recrutement de plusieurs testeurs (points de terminaison, serveurs) pour recueillir des statistiques authentiques et affiner les détections tout en garantissant la confidentialité des utilisateurs.
- **Affinement de la détection des comportements malveillants** :
  - Ajouter des règles de détection pour les tunnels DNS en capturant les schémas de requêtes potentiellement malveillants et éviter les faux positifs.
  - Réaliser des tests pour vérifier que les détections ne sont pas déclenchées par des fournisseurs légitimes de sous-domaines dynamiques.
- **Évaluation et ajustement des paramètres de détection** :
  - Mise en place de seuils de détection et ajustement des paramètres pour limiter les faux positifs et faux négatifs.
- **Documentation et tests finaux** :
  - Documentation complète du fonctionnement et des capacités du proxy DNS.
  - Tests finaux pour valider la performance du proxy et son efficacité en matière de détection.




