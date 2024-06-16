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
    c.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    service TEXT PRIMARY KEY,
                    password TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY,
                    password_hash TEXT
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

# Fonction pour ajouter un mot de passe de service
def add_password(service, password):
    key = generate_key(master_password)
    encrypted_password = encrypt_password(key, password)
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO passwords (service, password) VALUES (?, ?)", (service, encrypted_password))
    conn.commit()
    conn.close()

# Fonction pour récupérer un mot de passe de service
def get_password(service):
    key = generate_key(master_password)
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT password FROM passwords WHERE service = ?", (service,))
    result = c.fetchone()
    conn.close()
    if result:
        return decrypt_password(key, result[0])
    else:
        return None

# Initialisation de la base de données
init_db()

# Gestion des arguments de ligne de commande
parser = argparse.ArgumentParser(description='Gestionnaire de mots de passe.')
parser.add_argument('action', choices=['add', 'get'], help='Action à effectuer: add pour ajouter, get pour récupérer un mot de passe.')
parser.add_argument('service', help='Nom du service associé au mot de passe.')
args = parser.parse_args()

# Vérifier si un mot de passe maître est déjà stocké dans keyring pour cette session
master_password = keyring.get_password('password_manager', 'master_password')

if not master_password:
    # Saisie du mot de passe maître si non stocké
    master_password = getpass.getpass('Entrez le mot de passe maître: ')

    # Vérification du mot de passe maître
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT password_hash FROM master_password WHERE id = 1")
    result = c.fetchone()
    conn.close()

    if result:
        if not check_master_password(master_password, result[0]):
            print("Mot de passe maître incorrect.")
            exit()
    else:
        # Hache et stocke le mot de passe maître s'il n'existe pas
        hashed = hash_master_password(master_password)
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute("INSERT INTO master_password (id, password_hash) VALUES (1, ?)", (hashed,))
        conn.commit()
        conn.close()
    
    # Stocker le mot de passe maître dans keyring pour la session
    keyring.set_password('password_manager', 'master_password', master_password)

# Exécution de l'action demandée
if args.action == 'add':
    password = getpass.getpass('Entrez le mot de passe à ajouter: ')
    add_password(args.service, password)
    print(f"Mot de passe pour le service '{args.service}' ajouté avec succès.")
elif args.action == 'get':
    password = get_password(args.service)
    if password:
        pyperclip.copy(password)
        print(f"Mot de passe pour le service '{args.service}' copié dans le presse-papier.")
    else:
        print(f"Aucun mot de passe trouvé pour le service '{args.service}'.")
