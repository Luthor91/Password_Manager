# Gestionnaire de Mots de Passe - Utilitaire en Ligne de Commande

Ce gestionnaire de mots de passe est un utilitaire en ligne de commande simple permettant de stocker et de récupérer des mots de passe pour différents services de manière sécurisée.

## Prérequis

Avant d'utiliser cet utilitaire, assurez-vous d'avoir installé les outils suivants :

- Python (version 3.x recommandée)
- pip (pour l'installation des dépendances Python)
- Un environnement virtuel Python (recommandé pour isoler les dépendances du projet)

## Installation
  1. **Cloner le dépôt Git**

   ```bash
        git clone https://github.com/Luthor91/Password_Manager.git
        cd Password_Manager
   ```

  2. **Créer et activer un environnement virtuel (optionnel mais recommandé)**
   ```bash
        # Sur Windows
        python -m venv venv
        venv\Scripts\activate

        # Sur macOS/Linux
        python3 -m venv venv
        source venv/bin/activate
   ```
  3. **Installer les dépendances**

   ```bash
        pip install -r requirements.txt
   ```

Assurez-vous que toutes les dépendances nécessaires sont correctement installées dans votre environnement virtuel.

- **Utilisation**

    L'application demandera un mot de passe maître, ce mot de passe sera à renseigner une seule fois pour la session.

  - Pour exécuter l'application
  ```python
  python main.py
  ```

