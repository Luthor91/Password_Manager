import os
import psutil

# Fonction pour récupérer le nom du dernier logiciel exécuté
def get_last_executed_application():
    """
    Récupère et retourne le nom du dernier logiciel exécuté.
    Filtre les processus pour exclure ceux contenant "python" dans leur nom.

    Returns:
        str: Le nom du dernier processus exécuté ou un message d'erreur.
    """
    try:
        # Récupérer la liste des processus en cours d'exécution
        process_list = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_info = proc.as_dict(attrs=['pid', 'name', 'create_time'])
                process_list.append(proc_info)
            except psutil.NoSuchProcess:
                pass

        # Filtrer les processus pour exclure ceux contenant "python" dans leur nom
        filtered_processes = [proc for proc in process_list if 'python' not in proc['name'].lower()]

        # Trier par heure de création pour obtenir le dernier exécuté
        sorted_processes = sorted(filtered_processes, key=lambda x: x['create_time'], reverse=True)

        # Récupérer le nom du dernier processus exécuté
        if sorted_processes:
            last_process_name = sorted_processes[0]['name']
            return last_process_name
        else:
            return "Aucun processus récent trouvé."
    
    except Exception as e:
        return f"Erreur: {str(e)}"

# Fonction pour récupérer l'identifiant de l'utilisateur actuel
def get_current_user_id():
    """
    Récupère et retourne l'identifiant (nom d'utilisateur) de l'utilisateur actuel.

    Returns:
        str: L'identifiant de l'utilisateur actuel.
    """
    return os.getlogin()
