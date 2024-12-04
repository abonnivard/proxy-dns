import paramiko
import getpass
import os

def replay_error_via_ssh(server_ip, username, error_id, key_file="~/.ssh/id_rsa", container_name="dns_proxy"):
    """
    Se connecte à un serveur distant via SSH en utilisant une clé privée, et lance une fonction dans un conteneur Docker.
    :param server_ip: Adresse IP ou domaine du serveur SSH.
    :param username: Nom d'utilisateur pour la connexion SSH.
    :param error_id: ID de l'erreur à rejouer.
    :param key_file: Chemin vers la clé privée SSH (par défaut ~/.ssh/id_rsa).
    :param container_name: Nom du conteneur Docker où la fonction sera exécutée.
    """
    # Expande ~ pour obtenir le chemin absolu de la clé privée
    key_file = os.path.expanduser(key_file)

    # Demander la passphrase pour la clé privée
    passphrase = getpass.getpass("Entrez la passphrase pour votre clé SSH (si nécessaire) : ")

    # Initialiser la connexion SSH
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Charger la clé privée avec ou sans passphrase
        private_key = paramiko.RSAKey.from_private_key_file(key_file, password=passphrase)

        # Connexion au serveur avec la clé privée
        print(f"Connexion à {server_ip} avec la clé privée {key_file}...")
        ssh.connect(hostname=server_ip, username=username, pkey=private_key)
        print("Connexion réussie.")

        # Commande Docker pour exécuter le script dans le conteneur sans l'option -it
        command = f"docker exec {container_name} python /app/replay_error.py {error_id}"

        print(f"Exécution de la commande dans le conteneur Docker : {command}")
        stdin, stdout, stderr = ssh.exec_command(command)

        # Lire la sortie et les erreurs
        output = stdout.read().decode()
        errors = stderr.read().decode()

        if output:
            print("\n--- Résultat ---")
            print(output)
        if errors:
            print("\n--- Erreurs ---")
            print(errors)
    except Exception as e:
        print(f"Erreur : {e}")
    finally:
        ssh.close()
        print("Connexion SSH fermée.")

# Exemple d'utilisation
if __name__ == "__main__":
    server_ip = input("Entrez l'adresse IP ou le domaine du serveur SSH : ")
    username = input("Entrez votre nom d'utilisateur : ")
    error_id = input("Entrez l'ID de l'erreur à rejouer : ")
    replay_error_via_ssh(server_ip, username, error_id)
