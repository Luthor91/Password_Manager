import sqlite3
from cryptography.fernet import Fernet
import bcrypt
import argparse
import pyperclip
import getpass
import base64
import hashlib
import keyring

# Fonction pour initialiser la base de données
def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY,
                    service TEXT UNIQUE
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY,
                    service_id INTEGER,
                    username TEXT,
                    password TEXT,
                    FOREIGN KEY (service_id) REFERENCES services(id)
                )''')
    conn.commit()
    conn.close()

# Fonction pour hacher le mot de passe maître
def hash_master_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Fonction pour vérifier le mot de passe maître
def check_master_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Fonction pour générer une clé de chiffrement sécurisée à partir du mot de passe maître
def generate_key(password):
    sha256 = hashlib.sha256(password.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(sha256)

# Fonction pour chiffrer un mot de passe de service
def encrypt_password(key, password):
    fernet = Fernet(key)
    return fernet.encrypt(password.encode('utf-8'))

# Fonction pour déchiffrer un mot de passe de service
def decrypt_password(key, encrypted_password):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_password).decode('utf-8')

# Fonction pour ajouter un compte pour un service avec identifiant
def add_account(service, username):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    # Vérifier si le service existe déjà
    c.execute("SELECT id FROM services WHERE service = ?", (service,))
    service_row = c.fetchone()
    if not service_row:
        c.execute("INSERT INTO services (service) VALUES (?)", (service,))
        service_id = c.lastrowid
    else:
        service_id = service_row[0]

    # Demander le mot de passe pour l'identifiant spécifique
    password = getpass.getpass(f"Entrez le mot de passe pour '{username}' sur '{service}': ")

    # Ajouter le compte dans la table des comptes
    c.execute("INSERT INTO accounts (service_id, username, password) VALUES (?, ?, ?)", (service_id, username, password))
    
    conn.commit()
    conn.close()

# Fonction pour récupérer les identifiants associés à un service
def get_accounts(service):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    # Récupérer l'ID du service
    c.execute("SELECT id FROM services WHERE service = ?", (service,))
    service_row = c.fetchone()
    if not service_row:
        print(f"Aucun service '{service}' trouvé.")
        return
    
    service_id = service_row[0]
    
    # Récupérer les comptes pour ce service
    c.execute("SELECT username FROM accounts WHERE service_id = ?", (service_id,))
    accounts = c.fetchall()
    
    conn.close()
    
    if not accounts:
        print(f"Aucun compte trouvé pour le service '{service}'.")
    else:
        print(f"Identifiants disponibles pour le service '{service}':")
        for account in accounts:
            print(account[0])

# Fonction pour récupérer un mot de passe pour un compte spécifique
def get_password(service, username=None):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    # Récupérer l'ID du service
    c.execute("SELECT id FROM services WHERE service = ?", (service,))
    service_row = c.fetchone()
    if not service_row:
        print(f"Aucun service '{service}' trouvé.")
        return
    
    service_id = service_row[0]
    
    # Récupérer le mot de passe pour le compte spécifique ou le premier compte si aucun identifiant spécifié
    if username:
        c.execute("SELECT password FROM accounts WHERE service_id = ? AND username = ?", (service_id, username))
    else:
        c.execute("SELECT password FROM accounts WHERE service_id = ?", (service_id,))
    
    result = c.fetchone()
    conn.close()
    
    if result:
        return result[0]
    else:
        return None

# Initialisation de la base de données
init_db()

# Gestion des arguments de ligne de commande
parser = argparse.ArgumentParser(description='Gestionnaire de mots de passe.')
parser.add_argument('action', choices=['add', 'get'], help='Action à effectuer: add pour ajouter, get pour récupérer un mot de passe.')
parser.add_argument('service', help='Nom du service associé au mot de passe.')
parser.add_argument('username', nargs='?', help='Identifiant associé au compte (optionnel, pour la récupération).')
args = parser.parse_args()

# Exécution de l'action demandée
if args.action == 'add':
    if args.username:
        add_account(args.service, args.username)
    else:
        print("Erreur: L'identifiant (username) est requis pour ajouter un compte.")
elif args.action == 'get':
    if args.username is None:
        get_accounts(args.service)
    else:
        password = get_password(args.service, args.username)
        if password:
            pyperclip.copy(password)
            print(f"Mot de passe pour le service '{args.service}' et l'identifiant '{args.username}' copié dans le presse-papier.")
        else:
            print(f"Aucun mot de passe trouvé pour le service '{args.service}' et l'identifiant '{args.username}'.")
