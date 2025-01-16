# Installation et Configuration de Iodine pour DNS Tunneling

Ce guide explique comment installer et configurer **iodine** sur une VM Ubuntu afin de mettre en place un tunnel DNS permettant l'exfiltration de données via des requêtes DNS.

## 1. Concept de DNS Tunneling avec iodine

**DNS Tunneling** consiste à utiliser des requêtes DNS pour transmettre des données à un serveur distant. Avec **iodine**, les données sont encapsulées dans des sous-domaines de requêtes DNS envoyées par le client et interprétées par le serveur. Cela permet de contourner certaines restrictions réseau.

### Fonctionnement

1. **Serveur iodine** : Machine configurée pour écouter les requêtes DNS et décoder les données encapsulées dans les sous-domaines.
2. **Client iodine** : Machine qui envoie les données encapsulées dans les requêtes DNS, destinées au domaine contrôlé par le serveur iodine.

### Exemple de communication

Le client envoie une requête DNS vers un sous-domaine, comme `data1.data2.data3.example.com`. Cette requête DNS atteint le **serveur iodine**, qui extrait les données contenues dans `data1`, `data2`, `data3` et y répond.

## 2. Installation de iodine

### Prérequis

Assurez-vous d’avoir les droits d'administrateur et que votre système est à jour :

```bash
sudo apt update && sudo apt upgrade -y
```

### Installation

Sur Ubuntu, installez iodine en utilisant le gestionnaire de paquets :

```bash
sudo apt install iodine -y
```

## 3. Configuration du Serveur iodine

Pour configurer un serveur iodine, vous devez posséder un domaine que vous contrôlez.

1. **Posséder un domaine** : Enregistrez un domaine, par exemple `example.com`, auprès d’un service de noms de domaine (GoDaddy, OVH, etc.).

2. **Configurer les enregistrements DNS** :
   - Ajoutez un enregistrement **NS** pour votre domaine, de sorte que toutes les requêtes vers `example.com` et ses sous-domaines soient redirigées vers le serveur iodine.
   - Par exemple, configurez un enregistrement NS qui pointe `example.com` vers l’adresse IP de votre serveur iodine.

### Lancer le Serveur iodine

Exécutez le serveur en utilisant la commande suivante, en spécifiant le domaine que vous avez configuré et l’interface réseau :

```bash
sudo iodined -c -f 10.0.0.1 -P test tunnel.bonnivard.net
```

Cela lance le serveur en utilisant `example.com` comme domaine pour le tunnel et attribue l'adresse IP 10.0.0.1 au serveur dans le tunnel.

## 4. Configuration du Client iodine

Sur une autre machine, installez le client iodine :

```bash
sudo apt install iodine -y
```

### Connecter le Client au Serveur

Sur le client, lancez la commande suivante pour établir le tunnel DNS :

```bash
sudo iodine -I 50 -f -P test  tunnel.bonnivard.net
sudo iodine -I 50 -f -r 159.65.55.92 -P test tunnel.bonnivard.net
```

Iodine utilisera `example.com` pour envoyer des requêtes DNS vers le serveur. 

## 5. Vérification

Une fois connecté, vous pouvez vérifier la connectivité en utilisant la commande `ping` sur l’adresse IP attribuée au serveur dans le tunnel :

```bash
ping 10.0.0.1
```

Si le ping est réussi, la connexion au serveur DNS est établie.

## Notes

- **Posséder un domaine** : Ce domaine est nécessaire pour router les requêtes DNS vers votre serveur.
- **Enregistrement NS** : Configurez un enregistrement Nameserver (NS) pour rediriger les requêtes vers votre serveur iodine.
- **Encapsulation des données** : Les données sont encapsulées dans les sous-domaines des requêtes DNS pour être interprétées par le serveur.

## Références

- [Projet iodine sur GitHub](https://github.com/yarrick/iodine)
- [Documentation officielle de iodine](https://code.kryo.se/iodine/)

```
