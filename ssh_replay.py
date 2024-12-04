import paramiko

def replay_error_via_ssh(server_ip, username, error_id, key_file="~/.ssh/id_rsa"):
    """
    Se connecte à un serveur distant via SSH en utilisant une clé privée, rejoue une erreur DNS, puis se déconnecte.
    :param server_ip: Adresse IP ou domaine du serveur SSH.
    :param username: Nom d'utilisateur pour la connexion SSH.
    :param error_id: ID de l'erreur à rejouer.
    :param key_file: Chemin vers la clé privée SSH (par défaut ~/.ssh/id_rsa).
    """
    # Initialiser la connexion SSH
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connexion au serveur avec la clé privée
        print(f"Connexion à {server_ip} avec la clé privée {key_file}...")
        ssh.connect(hostname=server_ip, username=username, key_filename=key_file)
        print("Connexion réussie.")

        # Commande à exécuter sur le serveur
        command = f"python replay.py {error_id}"

        print(f"Exécution de la commande : {command}")
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
