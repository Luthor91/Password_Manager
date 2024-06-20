import json
import tkinter as tk
from tkinter import Image, messagebox, ttk
from PIL import Image, ImageTk

import pyperclip
import database as Database
import passwords as Passwords
import utilities as Utilities

# Constante globale pour la taille de la fenêtre
WINDOW_WIDTH = 500
WINDOW_HEIGHT = 400

class PasswordManagerApp(tk.Tk):
    max_attempts = 3
    current_attempts = 0

    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.resizable(False, False)  # Empêcher la redimension de la fenêtre

        # Charger et redimensionner l'image de fond
        self.background_image = Image.open("assets/background.jpg")
        self.background_image = self.background_image.resize((WINDOW_WIDTH, WINDOW_HEIGHT), Image.LANCZOS)
        self.background_photo = ImageTk.PhotoImage(self.background_image)

        # Initialisation de la base de données au démarrage
        Database.init_db()

        # Démarrer l'application
        self.start()

    def start(self):
        # Vérifier si l'utilisateur est déjà enregistré
        current_username = Utilities.get_current_user_id()
        user = Database.get_user_by_username(current_username)
        
        if not user:
            success, master_password = Passwords.create_user_with_master_password(current_username)
            if success:
                # Afficher l'écran de connexion avec le Master Password
                self.show_login_screen(master_password)
            else:
                self.show_error_message("Impossible de créer l'utilisateur. Veuillez réessayer.")
                self.destroy()  # Fermer l'application en cas d'erreur de création

        else:
            # Afficher directement l'écran de connexion si l'utilisateur est déjà enregistré
            self.show_login_screen()

    def show_error_message(self, message):
        # Créer une fenêtre Toplevel pour afficher le message d'erreur
        error_window = tk.Toplevel(self)
        error_window.title("Erreur")
        error_window.geometry("400x200")

        tk.Label(error_window, text=message).pack(padx=20, pady=20)

        # Mettre la fenêtre au premier plan
        error_window.attributes("-topmost", True)

        # Bloquer le focus sur cette fenêtre jusqu'à sa fermeture
        error_window.grab_set()
        error_window.wait_window()

    def show_login_screen(self, master_password=None):
        self.destroy_widgets()
        
        # Créer un Canvas avec une image de fond
        self.login_canvas = tk.Canvas(self, width=WINDOW_WIDTH, height=WINDOW_HEIGHT)
        self.login_canvas.pack(fill="both", expand=True)
        
        # Ajouter l'image de fond
        self.login_canvas.create_image(0, 0, image=self.background_photo, anchor="nw")
        
        # Ajouter les widgets sur le Canvas
        self.login_canvas.create_text(WINDOW_WIDTH//2, 50, text="Veuillez entrer votre Master Password :", fill="black")
        self.master_password_entry = tk.Entry(self, show='*')
        self.login_canvas.create_window(WINDOW_WIDTH//2, 80, window=self.master_password_entry)
        self.verify_button = tk.Button(self, text="Vérifier", command=self.verify_master_password)
        self.login_canvas.create_window(WINDOW_WIDTH//2, 120, window=self.verify_button)
        
        if master_password:
            self.login_canvas.create_text(WINDOW_WIDTH//2, 160, text="Votre Master Password est :", fill="red")
            self.master_password_display = tk.Entry(self, width=15)
            self.master_password_display.insert(0, master_password)
            self.master_password_display.config(state='readonly')
            self.login_canvas.create_window(WINDOW_WIDTH//2, 190, window=self.master_password_display)

    def verify_master_password(self):
        master_password = self.master_password_entry.get()
        if Passwords.verify_master_password(master_password):
            self.show_main_interface()
        else:
            self.current_attempts += 1
            remaining_attempts = self.max_attempts - self.current_attempts
            if remaining_attempts > 0:
                messagebox.showerror("Erreur", f"Mot de passe maître incorrect.\nIl vous reste {remaining_attempts} tentatives.")
            else:
                messagebox.showerror("Trop d'essais infructueux", "Vous avez dépassé le nombre d'essais autorisés.")
                self.destroy()  # Fermer l'application en cas de trop d'essais infructueux

    def show_main_interface(self):
        # Supprimer l'écran de connexion
        self.destroy_widgets()

        # Créer une nouvelle frame pour l'interface principale
        self.main_interface_frame = tk.Frame(self)
        self.main_interface_frame.pack(fill=tk.BOTH, expand=True)

        # Colonne 1 : Ajouter un service, un identifiant et un mot de passe
        add_service_frame = tk.LabelFrame(self.main_interface_frame, text="Ajouter un service")
        add_service_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        tk.Label(add_service_frame, text="Service :").grid(row=0, column=0, padx=5, pady=5)
        self.service_entry = tk.Entry(add_service_frame)
        self.service_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(add_service_frame, text="Identifiant :").grid(row=1, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(add_service_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(add_service_frame, text="Mot de passe :").grid(row=2, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(add_service_frame, show='*')
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        add_button = tk.Button(add_service_frame, text="Ajouter", command=self.add_service)
        add_button.grid(row=3, columnspan=2, pady=10)

        # Colonne 2 : Sélectionner un service et un identifiant existant
        select_service_frame = tk.LabelFrame(self.main_interface_frame, text="Sélectionner un service")
        select_service_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        tk.Label(select_service_frame, text="Service :").grid(row=0, column=0, padx=5, pady=5)
        self.service_select = ttk.Combobox(select_service_frame, values=self.get_all_services())
        self.service_select.grid(row=0, column=1, padx=5, pady=5)
        self.service_select.bind("<<ComboboxSelected>>", self.populate_username_select)

        tk.Label(select_service_frame, text="Identifiant :").grid(row=1, column=0, padx=5, pady=5)
        self.username_select = ttk.Combobox(select_service_frame)
        self.username_select.grid(row=1, column=1, padx=5, pady=5)

        copy_button = tk.Button(select_service_frame, text="Copier Mot de passe", command=self.copy_password)
        copy_button.grid(row=2, columnspan=2, pady=10)



    def destroy_widgets(self):
        # Supprimer tous les widgets de la fenêtre principale
        for widget in self.winfo_children():
            widget.destroy()

    def get_all_services(self):
        return Database.get_all_services()

    def populate_username_select(self, event):
        selected_service = self.service_select.get()
        usernames = Database.get_usernames_for_service(selected_service)
        self.username_select['values'] = usernames

    def add_service(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if service and username and password:
            # Chiffrer le mot de passe avant de l'ajouter à la base de données
            encrypted_password = Passwords.encrypt_password(password)
            
            # Convertir la chaîne JSON en dictionnaire
            try:
                encrypted_data = json.loads(encrypted_password)
            except json.JSONDecodeError:
                raise ValueError("Données de chiffrement invalides")

            # Vérifier que les données nécessaires sont présentes
            required_keys = {'ciphertext', 'tag', 'nonce', 'salt'}
            if not required_keys.issubset(encrypted_data.keys()):
                raise ValueError("Données de chiffrement invalides")
            
            # Ajouter le compte chiffré à la base de données
            Database.add_account(service, username, encrypted_data, Utilities.get_current_user_id())

            # Rafraîchir les services disponibles dans la Combobox
            self.service_select['values'] = self.get_all_services()

            # Effacer les champs après ajout
            self.service_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)

            messagebox.showinfo("Service ajouté", "Service ajouté avec succès.")
        else:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")

    def copy_password(self):
        selected_service = self.service_select.get()
        selected_username = self.username_select.get()

        if selected_service and selected_username:
            # Récupérer le mot de passe chiffré depuis la base de données
            encrypted_password = Database.get_password(selected_service, selected_username)

            if encrypted_password:
                # Déchiffrer le mot de passe
                try:
                    decrypted_password = Passwords.decrypt_password(encrypted_password)
                except ValueError:
                    messagebox.showerror("Erreur", "Erreur de déchiffrement : intégrité altérée ou mot de passe incorrect")
                    return

                # Copier le mot de passe déchiffré dans le presse-papiers
                pyperclip.copy(decrypted_password)

                messagebox.showinfo("Mot de passe copié", "Mot de passe copié dans le presse-papiers.")
            else:
                messagebox.showerror("Erreur", "Impossible de récupérer le mot de passe.")
        else:
            messagebox.showerror("Erreur", "Veuillez sélectionner un service et un identifiant.")


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()