import base64
import hashlib
import json
import os
import platform
import random
import sqlite3
import string
import getpass
from dotenv import find_dotenv, load_dotenv, set_key
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode, b64decode
import wmi
import stat
import subprocess
import database as Database
import winreg
from Crypto.Random import get_random_bytes

def get_hardware_id():
    """
    Retourne un identifiant unique basé sur le matériel.
    Utilise le numéro de série du disque dur sur Windows et l'adresse MAC sur Linux/macOS.
    """
    if platform.system() == "Windows":
        # Utiliser le numéro de série du disque dur sur Windows
        try:
            c = wmi.WMI()
            for disk in c.Win32_DiskDrive():
                return disk.SerialNumber.strip()
        except ImportError:
            pass
    elif platform.system() == "Linux":
        # Utiliser l'adresse MAC sur Linux
        try:
            for line in os.popen("ifconfig"):
                if "ether" in line:
                    return line.split()[1].strip()
        except Exception:
            pass
    elif platform.system() == "Darwin":
        # Utiliser l'adresse MAC sur macOS
        try:
            for line in os.popen("ifconfig"):
                if "ether" in line:
                    return line.split()[1].strip()
        except Exception:
            pass
    return "default_hardware_id"

def get_salt():
    """
    Retourne un sel unique basé sur le nom d'utilisateur de l'ordinateur.
    """
    return hashlib.sha256(os.getlogin().encode('utf-8')).hexdigest()[:16]

def get_pepper():
    """
    Retourne un pepper unique basé sur l'identifiant matériel de l'ordinateur.
    """
    hardware_id = get_hardware_id()
    return hashlib.sha256(hardware_id.encode('utf-8')).hexdigest()[:16]

def generate_master_password():
    """
    Génère et retourne un mot de passe maître aléatoire de 12 caractères.
    """
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))

def get_master_password():
    """
    Récupère et retourne le hash du mot de passe maître stocké pour l'utilisateur actuel.
    """
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
    """
    Crée un nouvel utilisateur avec un mot de passe maître.
    Retourne le succès de la création et le mot de passe maître généré.
    """
    master_password = generate_master_password()
    salt = get_salt()
    pepper = get_pepper()
    
    hash_input = master_password.encode('utf-8') + salt.encode('utf-8') + pepper.encode('utf-8')
    master_password_hash = hashlib.sha256(hash_input).hexdigest()
    
    success = Database.create_user(username, master_password_hash)
    
    return success, master_password

def encrypt_password(password):
    """
    Chiffre le mot de passe donné en utilisant AES en mode GCM.
    Retourne les données chiffrées sous forme de chaîne JSON.
    """
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

def decrypt_password(encrypted_password):
    """
    Déchiffre le mot de passe chiffré donné.
    Retourne le mot de passe en texte clair ou lève une erreur si le déchiffrement échoue.
    """
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

        key = PBKDF2(master_password, salt + pepper, dkLen=32)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return plaintext.decode('utf-8')
    except (KeyError, ValueError):
        raise ValueError("Erreur de déchiffrement : intégrité altérée ou mot de passe incorrect")

def verify_master_password(master_password):
    """
    Vérifie le mot de passe maître donné en le comparant avec le hash stocké.
    Retourne True si le mot de passe est correct, sinon False.
    """
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    current_username = getpass.getuser()
    c.execute("SELECT master_password_hash FROM users WHERE username = ?", (current_username,))
    stored_hash = c.fetchone()

    if stored_hash:
        stored_hash = stored_hash[0]
        # Utilisation du même processus pour vérifier le mot de passe maître
        hash_input = master_password.encode('utf-8') + get_salt().encode('utf-8') + get_pepper().encode('utf-8')
        master_password_entered = hashlib.sha256(hash_input).hexdigest()
        if stored_hash == master_password_entered:
            conn.close()
            return True

    conn.close()
    return False
