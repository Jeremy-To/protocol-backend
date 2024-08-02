# Analyseur de fichiers PCAP

Cette application Flask fournit une API pour analyser des fichiers PCAP (Packet Capture) et générer des statistiques sur les protocoles réseau utilisés.

## Fonctionnalités

- Analyse des fichiers PCAP
- Calcul des statistiques par protocole :
  - Nombre de paquets
  - Quantité de données transférées
  - Répartition des données client vers serveur et serveur vers client
- Classement des protocoles par nombre de paquets et quantité de données transférées

## Prérequis

- Python 3.6+
- Flask
- tshark (Wireshark command line tool)

## Installation

1. Clonez ce dépôt
2. Installez les dépendances :
pip install flask
3. Assurez-vous que tshark est installé et accessible dans le PATH du système

## Utilisation

1. Lancez l'application :
python app.py
2. Envoyez une requête POST à `/analyze` avec le fichier PCAP à analyser :

```python
import requests

url = "http://localhost:5000/analyze"
files = {"file": open("sample.pcap", "rb")}

response = requests.post(url, files=files)
print(response.json())
```
Réponse de l'API
L'API renvoie un JSON contenant deux listes :

protocols_by_packet_count : Protocoles triés par nombre de paquets

protocol : Nom du protocole
total_packets : Nombre total de paquets
percentage : Pourcentage des paquets totaux


protocols_by_data_transferred : Protocoles triés par quantité de données transférées

protocol : Nom du protocole
total_mb : Total des données transférées en Mo
client_to_server_mb : Données du client vers le serveur en Mo
server_to_client_mb : Données du serveur vers le client en Mo



Gestion des erreurs
L'API renvoie des messages d'erreur appropriés dans les cas suivants :

Aucun fichier n'est fourni
tshark n'est pas installé ou n'est pas trouvé dans le PATH
Erreur lors de l'exécution de tshark

Sécurité
Cette application est conçue pour un usage local ou dans un environnement de confiance. Assurez-vous de mettre en place des mesures de sécurité appropriées si vous la déployez sur un serveur accessible publiquement.
Licence
Ce projet est sous licence MIT.
