# version 39 - 31 05 2024

# ------------------------------------------------------------------------------------------
#                                       OBJECTIF
# -----------------------------------------------------------------------------------------
# Ce script récupère les mails "NON LUS" d'une boîte mails en utilisant son login et mot de passe ainsi que le protocole IMAP
# Une fois le mail récupéré, il est Tagué "LU".
# Une fois le/les mail(s) récupéré(s), les pièces jointes sont extraites et archivées sous forme de ZIP ou pas, au choix, protégées avec un mot de passe
# Une autre partie s'occupe du parsing du mail brute pour récréer les champs principaux, décoder le base64 du corps du message
# Dans ce fichier parsé, il y aura la détection des IPv4, IPv6, noms de domaines. Ces valeurs seront mises dans un champs IOC pour être analysé par Splunk
# En tout état de cause l'en-tête du mail est gardé et mise dans un champs en cas de besoin pour l'analyste Cyber

# ------------------------------------------------------------------------------------------
#                                 IMPORT DES MODULES PYTHON
# -----------------------------------------------------------------------------------------

import imaplib   # A voir s'il faut installer cette lib
import email     # idem
import os
import re
import hashlib   # idem
import base64
import pyzipper  # module à installer : pip install pyzipper

# ------------------------------------------------------------------------------------
#                                    LES VARIABLES
#
#       (les utilisateurs peuvent modifier cette partie au besoin sans problème)
# ------------------------------------------------------------------------------------

# Paramètres de connexion IMAP (FQDN + LOGIN + MOT DE PASSE)
IMAP_SERVER = "monServeurExchange.fr"
IMAP_PORT = 993
EMAIL = "maBoiteMail@monServeurExchange.fr"
PASSWORD = "leMDPdeMaBoiteMail+-*/"

# Choisir l'algorithme de hachage : 'md5', 'sha1' ou 'sha256'
# Il sera utilisé dans les noms des pièces jointes et sera mis dans les champs du fichier qui ira dans splunk
HASH_ALGORITHM = 'sha256'

# Mot de passe pour le chiffrement AES du fichier zip
ZIP_PASSWORD = b"P@ssword0fZIP"

# Dossiers de destination pour enregistrer les e-mails, les pièces jointes et les informations extraites
MAILS_DIR = "/script/mails_raw" # mails
ATTACHMENTS_DIR = "/script/attachments" # PJ
#ATTACHMENTS_DIR = "/script_orion/script/zip_from_ftp" # PJ
INFO_DIR = "/script/rapport_to_splunk" # fichier à Forward vers Splunk


############################################################################################
#
#   A PARTIR DE LA TU CASSES TU RECONSTRUIS !!! Don't touch please !!! 
#

# ------------------------------------------------------------------------------------------
#                                   LES SOUS-FONCTIONS
# ------------------------------------------------------------------------------------------

# Fonction pour créer un dossier s'il n'existe pas
def create_directory_if_not_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Fonction pour remplacer les occurrences de http, https et www
def replace_links(content):
    content = re.sub(r'http://', 'hXXXXp://', content)
    content = re.sub(r'https://', 'hXXXXps://', content)
    content = re.sub(r'www', 'wwwXXXX', content)
    return content

# Fonction pour nettoyer les destinataires du fichier allant vers Splunk
def clean_recipients(recipients):
    cleaned_recipients = []
    for recipient in recipients:
        recipient = recipient.strip()  # Enlever les espaces au début et à la fin
        recipient = re.sub(r'\s+', ' ', recipient)  # Remplacer les espaces multiples par un seul espace
        cleaned_recipients.append(recipient)
    return cleaned_recipients

# Fonction pour calculer l'empreinte numérique MD5, SHA-1 ou SHA-256 en fonction de l'algorithme spécifié
def calculate_hash(file_data, algorithm):
    if algorithm == 'md5':
        hash_func = hashlib.md5()
    elif algorithm == 'sha1':
        hash_func = hashlib.sha1()
    elif algorithm == 'sha256':
        hash_func = hashlib.sha256()
    else:
        raise ValueError("Unknown algorithm") # si fonction inconnue
    hash_func.update(file_data)
    return hash_func.hexdigest()

# ------------------------------------------------------------------------------------------
#                                   LES FONCTIONS
# ------------------------------------------------------------------------------------------

# Fonction pour extraire les informations du mail et les enregistrer dans un fichier texte
# Creation et ordre des champs du fichier info
def extract_info_from_email(msg, mail_file_name, attachments_info):
    date_str = msg["Date"]
    subject = msg["Subject"]
    message_id = msg["Message-ID"]
    sender = msg["From"]
    recipients = msg.get_all("To", [])
    html_content = ""
    base64_content = ""
    attachments = []

    # Extraire l'en-tête du mail
    email_header_lines = []
    for line in str(msg).split('\n'):
        line = line.strip()
        if not line:  # Arrêter dès qu'on rencontre une ligne vide
            break
        email_header_lines.append(line)
    email_header = '\n'.join(email_header_lines)

    # Extraire le contenu HTML (corps + pièces jointes) et les pièces jointes (exctraction + decode B64)
    for part in msg.walk():
        content_type = part.get_content_type()
        content_transfer_encoding = part.get("Content-Transfer-Encoding")
        if content_type == "text/html": # si texte
            charset = part.get_content_charset() or 'utf-8' # cet encodage peut résoudre certains problèmes
            payload = part.get_payload(decode=True)
            base64_payload = part.get_payload()  # Garde le contenu base64 original
            if content_transfer_encoding == "base64": # si texte en base64
                payload = base64.b64decode(base64_payload)
            html_content += payload.decode(charset, 'ignore')
            base64_content = base64_payload  # Sauvegarde le contenu base64
        elif part.get("Content-Disposition") is not None:
            filename = part.get_filename()
            if filename:
                attachments.append(filename)

    # Modifier le contenu HTML
    html_content = replace_links(html_content)

    # Supprimer tout ce qui suit </html> dans le contenu HTML
    html_content = html_content.split('</html>')[0] + '</html>'

    # Extraire les liens détectés et les adresses IP V4 dans le contenu HTML
    links_detected = list(set(re.findall(r'hXXXXp://[^\s]+|hXXXXps://[^\s]+', html_content)))
    ip_addresses = list(set(re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', html_content))) # on peu optimiser la REGEX si besoin

    # Extraire les adresses IPv6 dans le contenu HTML
    ipv6_addresses = list(set(re.findall(r'(?:(?<![0-9a-fA-F:])|(?<=\s))(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])', html_content)))

    # Ajouter les adresses IPv6 aux liens détectés
    links_detected.extend(ipv6_addresses)

    # Nettoyer les destinataires
    cleaned_recipients = clean_recipients(recipients)

    # Extraire les adresses IP V4 et les noms de domaines des liens détectés
    ioc_list = ip_addresses.copy()
    for link in links_detected:
        # Extraction des noms de domaine, en excluant les sous-domaines comme "www"
        match = re.search(r'(?<=://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', link)
        if match:
            domain = match.group(0)
            # Supprimer les caractères non alphabétiques et non numériques autour du domaine
            domain = re.sub(r'^[^a-zA-Z0-9]+|[^a-zA-Z0-9]+$', '', domain)
            # Supprimer "www." ou tout autre sous-domaine
            domain_parts = domain.split('.')
            if len(domain_parts) > 2 and domain_parts[0].lower() == 'www':
                domain = '.'.join(domain_parts[1:])
            elif len(domain_parts) > 2:
                domain = '.'.join(domain_parts[-2:])
            ioc_list.append(domain)

    # Ajouter les adresses IPv6 à la liste IOC
    ioc_list.extend(ipv6_addresses)

    # Supprimer les doublons de la liste IOC
    ioc_list = list(set(ioc_list))

    # Nettoyer les liens détectés
    cleaned_links = []
    for link in links_detected:
        # Supprimer le contenu entre les balises HTML
        cleaned_link = re.sub(r'<[^>]*>', '', link)
        # Supprimer les guillemets à la fin
        cleaned_link = re.sub(r'["<]$', '', cleaned_link)
        cleaned_links.append(cleaned_link)

    # Générer le contenu du fichier texte avec les informations extraites
    info_content = "date={}|||subject={}|||message-ID={}|||sender={}|||".format(date_str, subject, message_id, sender)
    info_content += "recipients={}|||".format(", ".join(cleaned_recipients))
    info_content += "links_detected={}|||".format(", ".join(cleaned_links))
    info_content += "IOC={}|||".format(",".join(ioc_list))

    for idx, attachment in enumerate(attachments, start=1):
        info_content += "attachment_name_{}={}|||".format(idx, attachment)
        attachment_hash = attachments_info.get(attachment, 'Not available')
        info_content += "attachment_hash_{}={}|||".format(idx, attachment_hash)

    info_content += "html_content={}|||".format(html_content)
    info_content += "email_header={}|||".format(email_header)

    # Enregistrer les informations extraites dans un fichier texte + Nommage fichier parsé qui ira vers Splunk
    info_file_path = os.path.join(INFO_DIR, mail_file_name.replace(".eml", "_TO_ANALYZE.csv")) # on utilisera le même nommage que le mail en remplaçant sont extension par autre chose
    with open(info_file_path, "w") as info_file:
        info_file.write(info_content)

# ------------------------------------------------------------------------------------------
#                                   LA FONCTION PRINCIPALE
# ------------------------------------------------------------------------------------------

# Fonction pour télécharger les e-mails et les pièces jointes
def analyse_emails():
    # Utilisation du module IMAP et emplacement de recherche des mail
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(EMAIL, PASSWORD)
    mail.select("inbox")

    # Recherche et récupération des mail NON LU
    result, data = mail.search(None, "UNSEEN")
    if result == "OK":
        for num in data[0].split():
            result, data = mail.fetch(num, "(RFC822)")
            if result == "OK":
                raw_email = data[0][1]
                msg = email.message_from_bytes(raw_email)

                # Récupération des info pour le nommage
                message_id = msg["Message-ID"]
                date_str = msg["Date"]
                date = email.utils.parsedate_to_datetime(date_str)
                date_formatted = date.strftime("%Y%m%d_%H%M%S")
                sender = msg["From"]

                # Creation des répertoires si inexistant
                create_directory_if_not_exists(MAILS_DIR)
                create_directory_if_not_exists(ATTACHMENTS_DIR)
                create_directory_if_not_exists(INFO_DIR)

                # Nommage du mail extrait
                mail_file_name = "{}_{}.eml".format(date_formatted, message_id) # , re.sub(r'\s+', '', sender))
                mail_file_path = os.path.join(MAILS_DIR, mail_file_name)

                # Ouvrir le mail
                with open(mail_file_path, "wb") as f:
                    f.write(raw_email)

                # PJ : extraction + hash + nommage avec le hash
                attachments_info = {}
                if msg.get_content_maintype() == "multipart":
                    for part in msg.walk():
                        if part.get_content_maintype() == "multipart" or part.get("Content-Disposition") is None:
                            continue
                        filename = part.get_filename()
                        if filename:
                            file_data = part.get_payload(decode=True)
                            attachment_hash = calculate_hash(file_data, HASH_ALGORITHM)
                            #new_filename = "{}_{}".format(attachment_hash, filename)
                            new_filename = "{}".format(attachment_hash)
                            attachments_info[filename] = attachment_hash
                            file_path = os.path.join(ATTACHMENTS_DIR, new_filename)
                            with open(file_path, "wb") as file:
                                file.write(file_data)

                # Marquer l'e-mail comme lu
                extract_info_from_email(msg, mail_file_name, attachments_info)
                mail.store(num, "+FLAGS", "\\Seen")
                # Cloture de la fonction principale
                mail.close()
                mail.logout()

                # Les fonction suivantes permettent de faire des ZIP des pièces jointes avec MDP
                """
                # Créer un fichier zip s'il y a des pièces jointes
                if attachments_info:
                    zip_file_name = "{}_{}_{}.zip".format(date_formatted, message_id, re.sub(r'\s+', '', sender))
                    zip_file_path = os.path.join(ATTACHMENTS_DIR, zip_file_name)
                    with pyzipper.AESZipFile(zip_file_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zipf:
                        zipf.setpassword(ZIP_PASSWORD)  # Définir le mot de passe pour le chiffrement AES (voir tout en haut pour le mot de passe)
                        for attachment_name, attachment_hash in attachments_info.items():
                            file_path = os.path.join(ATTACHMENTS_DIR, "{}_{}".format(attachment_hash, attachment_name))
                            zipf.write(file_path, os.path.basename(file_path))
                """
                """
                # Créer un fichier zip pour chaque pièce jointe
                if attachments_info:
                    for attachment_name, attachment_hash in attachments_info.items():
                        #zip_file_name = "{}_{}_{}.zip".format(date_formatted, message_id, re.sub(r'\s+', '', sender), attachment_name)
                        zip_file_name = "{}_{}.zip".format(date_formatted, message_id)
                        zip_file_path = os.path.join(ATTACHMENTS_DIR, zip_file_name)

                        try:
                            with pyzipper.AESZipFile(zip_file_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zipf:
                                zipf.setpassword(ZIP_PASSWORD)  # Définir le mot de passe pour le chiffrement AES
                                file_path = os.path.join(ATTACHMENTS_DIR, "{}_{}".format(attachment_hash, attachment_name))

                                # Vérifiez si le fichier existe avant de l'ajouter au ZIP
                                if os.path.exists(file_path):
                                    #print(f"Ajout du fichier {file_path} au fichier ZIP {zip_file_path}")
                                    #zipf.write(file_path, os.path.basename(file_path)) # NOM de fichier : hash_nom.extension
                                    zipf.write(file_path, attachment_hash) # NOM de fichier : hash
                                    #print(f"Fichier {file_path} ajouté à {zip_file_path}.")
                                else:
                                    print(f"Le fichier {file_path} n'existe pas.")
                                    # Ajout de messages de débogage
                                    print(f"Vérifiez si le fichier est dans {ATTACHMENTS_DIR} et porte le nom {attachment_hash}_{attachment_name}.")
                        except Exception as e:
                            print(f"OOUPSSSS Erreur lors de la création du fichier ZIP {zip_file_path}: {e}")

                    # Supprimer les fichiers joints non zippés
                    for attachment_name in attachments_info.keys():
                        attachment_hash = attachments_info[attachment_name]
                        file_path = os.path.join(ATTACHMENTS_DIR, "{}_{}".format(attachment_hash, attachment_name))
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        else:
                            print("Le fichier {} n'existe pas.".format(file_path))
                """




# ------------------------------------------------------------------------------------------
#                                   APPEL GENERAL
# ------------------------------------------------------------------------------------------
if __name__ == "__main__":
    analyse_emails()
