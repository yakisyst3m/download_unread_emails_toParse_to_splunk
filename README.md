## Download Unread Emails to Parse to splunk / Téléchargez les e-mails non lus à analyser pour splunk



**But :**  
Ce script récupère les mails "NON LUS" d'une boîte mails présente sur un serveur Exchange, en utilisant son login et mot de passe ainsi que le protocole IMAP.
Une fois le mail récupéré, il est Tagué "LU".

**Extractions :**  
Une fois le/les mail(s) récupéré(s), les pièces jointes sont extraites et archivées sous forme de ZIP ou pas, au choix, protégées avec un mot de passe.
Il y a y différente parties proposée à la fin du script. Par défaut la compression a été désactivée en mettant en commentaire les lignes concernées.

**Parsing :**  
Une autre partie s'occupe du parsing du mail brute pour récréer les champs principaux, décoder le base64 du corps du message
Dans ce fichier parsé, il y aura la détection des IPv4, IPv6, noms de domaines. 
Ces valeurs seront mises dans un champs IOC pour être analysé par un sevreur Splunk.

**Nota :**  
En tout état de cause l'en-tête du mail est gardé et mise dans un champs en cas de besoin pour l'analyste Cyber
