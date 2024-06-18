import json
import sqlite3
import hashlib
from tkinter import messagebox
import database as Database
import passwords as Passwords
import utilities as Utilities
import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import string
import random

# Connexion à la base de données
def connect_db():
    return sqlite3.connect('passwords.db')

def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()

    # Création des tables (services, accounts, users)
    c.execute('''CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (service_id) REFERENCES services(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )''')

    c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                master_password_hash TEXT NOT NULL
            )''')

    conn.commit()
    conn.close()
    
def create_user(username, master_password_hash):
    conn = connect_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, master_password_hash) VALUES (?, ?)",
                  (username, master_password_hash))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False
    
# Fonction pour ajouter un service
def add_service(self):
    service = self.service_select.get()
    username = self.username_select.get()
    password = self.password_entry.get()

    if service and username and password:
        encrypted_password = Passwords.encrypt_password(password)
        
        try:
            encrypted_data = json.loads(encrypted_password)
        except json.JSONDecodeError:
            messagebox.showerror("Erreur", "Données de chiffrement invalides")
            return

        # Supposons que vous ayez une méthode pour obtenir l'ID de l'utilisateur actuel
        user_id = Utilities.get_current_user_id()
        
        # Ajouter le compte chiffré à la base de données
        Database.add_account(service, username, json.dumps(encrypted_data), user_id)
        
        # Mettre à jour la liste des services disponibles dans la combobox
        self.service_select['values'] = self.get_all_services()
        
        # Effacer les champs après ajout
        self.username_select.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        
        messagebox.showinfo("Service ajouté", "Service ajouté avec succès.")
    else:
        messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")

# Fonction pour ajouter un compte (identifiant et mot de passe)
def add_account(service, username, encrypted_password, user_id):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()

    # Vérifier si le service existe déjà dans la table des services
    c.execute("SELECT id FROM services WHERE name = ?", (service,))
    result = c.fetchone()
    if result:
        service_id = result[0]
    else:
        # Si le service n'existe pas, l'ajouter et récupérer son ID
        c.execute("INSERT INTO services (name) VALUES (?)", (service,))
        service_id = c.lastrowid

    # Convertir le dictionnaire en une chaîne JSON
    encrypted_password_json = json.dumps(encrypted_password)

    # Insérer l'enregistrement dans la table accounts
    c.execute("INSERT INTO accounts (service_id, username, password, user_id) VALUES (?, ?, ?, ?)",
              (service_id, username, encrypted_password_json, user_id))
    
    conn.commit()
    conn.close()
    
# Fonction pour récupérer tous les services existants
def get_all_services():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT name FROM services ORDER BY name")
    services = [row[0] for row in c.fetchall()]
    conn.close()
    return services

# Fonction pour récupérer les identifiants pour un service donné
def get_usernames_for_service(service):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    # Requête mise à jour pour correspondre aux noms de colonnes et de tables actuels
    c.execute("""
        SELECT username 
        FROM accounts 
        WHERE service_id = (SELECT id FROM services WHERE name = ?) 
        ORDER BY username
    """, (service,))
    
    usernames = [row[0] for row in c.fetchall()]
    conn.close()
    return usernames

# Fonction pour récupérer le mot de passe pour un service et un identifiant donnés
def get_password(service, username):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    # Assurez-vous que la table services a une colonne name
    c.execute("""
        SELECT password 
        FROM accounts 
        WHERE service_id = (SELECT id FROM services WHERE name = ?) 
        AND username = ?
    """, (service, username))
    
    result = c.fetchone()
    conn.close()
    
    if result:
        return result[0]
    return None

# Fonction pour récupérer un utilisateur par nom d'utilisateur
def get_user_by_username(username):
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    return user