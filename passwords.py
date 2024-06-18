import base64
import hashlib
import json
import os
import random
import sqlite3
import string
import subprocess
import database as Database
import getpass 
import winreg

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

# Ensure PEPPER is set as an environment variable
if "PEPPER" not in os.environ:
    os.environ["PEPPER"] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))

def get_salt():
    return hashlib.sha256(os.getlogin().encode('utf-8')).hexdigest()[:16]

def get_pepper():
    return os.environ["PEPPER"]

def generate_master_password():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))

def get_master_password():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()

    current_username = getpass.getuser()
    c.execute("SELECT * FROM users WHERE username = ?", (current_username,))
    user = c.fetchone()
    
    if user:
        stored_hash = user[2]
        conn.close()
        return stored_hash

    conn.close()
    return None

def create_user_with_master_password(username):
    master_password = generate_master_password()
    salt = get_salt()
    pepper = get_pepper()
    
    hash_input = master_password.encode('utf-8') + salt.encode('utf-8') + pepper.encode('utf-8')
    master_password_hash = hashlib.sha256(hash_input).hexdigest()
    
    success = Database.create_user(username, master_password_hash)
    
    return success, master_password

# Fonction pour chiffrer un mot de passe
def encrypt_password(password):
    salt = get_salt().encode('utf-8')
    pepper = get_pepper().encode('utf-8')
    master_password = get_master_password()
    key = PBKDF2(master_password, salt + pepper, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    
    encrypted_data = {
        'ciphertext': b64encode(ciphertext).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8'),
        'nonce': b64encode(cipher.nonce).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8')
    }

    return json.dumps(encrypted_data)

# Fonction pour déchiffrer un mot de passe
def decrypt_password(encrypted_password):
    try:
        encrypted_data = json.loads(encrypted_password)
    except json.JSONDecodeError:
        raise ValueError("Données de chiffrement invalides")
    
    try:
        ciphertext = b64decode(encrypted_data['ciphertext'])
        tag = b64decode(encrypted_data['tag'])
        nonce = b64decode(encrypted_data['nonce'])
        salt = get_salt().encode('utf-8') 
        pepper = get_pepper().encode('utf-8')
        master_password = get_master_password()

        # Utilisation du salt et pepper stockés pour dériver la clé
        key = PBKDF2(master_password, salt + pepper, dkLen=32)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return plaintext.decode('utf-8')
    except (KeyError, ValueError):
        raise ValueError("Erreur de déchiffrement : intégrité altérée ou mot de passe incorrect")

def verify_master_password(master_password):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()

    current_username = getpass.getuser()
    c.execute("SELECT * FROM users WHERE username = ?", (current_username,))
    user = c.fetchone()
    
    if user:
        stored_hash = user[2]

        # Utilisation du même processus pour vérifier le mot de passe maître
        hash_input = master_password.encode('utf-8') + get_salt().encode('utf-8') + get_pepper().encode('utf-8')
        master_password_entered = hashlib.sha256(hash_input).hexdigest()

        if stored_hash == master_password_entered:
            conn.close()
            return True

    conn.close()
    return False