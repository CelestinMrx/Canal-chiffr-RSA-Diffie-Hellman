# Canal de communication chiffré

Ce projet universitaire présente une implémentation d’un canal de communication chiffré entre deux entités (Alice et Bob). Il illustre l’utilisation combinée de certificats RSA, d’un échange de clés Diffie-Hellman, de signatures numériques et d’un MAC pour assurer confidentialité, authentification et intégrité des messages.

## Authentification
### Certificat + Clé 

Alice et Bob utilise openssl pour générer un certificat autosigné et une clé RSA public et une clé privée.

### Echange de clé

Alice et Bob s'échange leurs clé public en claire (aucun risque pas de panique)

### Echange de Certificat

Alice utilise la clé public de Bob pour chiffrer et envoyer sont certificat à Bob.  
Une fois reçu Bob déchiffre le certificat de Alice Avec sa clé privée. 
Maintenant Bob sait qu'il parle avec Alice, il envoie donc sont certificat plus celui d'Alice (pour confirmer qu'il la bien reçu) chiffrer avec la clé de Alice.  
Dernière étapes, Alice à la confirmation qu'elle parle avec Bob, elle peut envoyer un nombre premier et son générateur (choisi dans une banque de données public pour être sur d'avoir des valeur sécurisé). Le message sera signé pour assurer l'intégrité du message.  
Pour la signature, on va dans un premier temps hacher le message puis ajouter un padding pour le chiffrer avec la clé privée.
De cette façon le hash de la signature pourra être décodé par la clé public, il suffira ensuite de vérifier que les hash correcpondent.

### Deffie-Hellman

Alice et Bob vont pourvoir tous les deux s'envoyer `A = g^a mod p` (Alice) et `B = g^b mod p` (Bob).
Ici a et b sont des nombres aléatoires entre 0 et p-1.  
Pour s'envoyer A et B, Alice et Bob vont devoir aussi faire la même signature expliqué juste avant.
Une fois reçu, Alice et Bob peuvent créer leurs nouvelle clé symétrique pour leur communication `B^a` (Alice) et `A^b` (Bob).  


## Sécurisation communication privée
### MAC

Pour sécurisé la communication, Alice et Bob vont utilisé une fonction MAC pour pouvoir certifier l'intégité et l'authenticité des message reçu.  
Pour ce faire, comme maintenant Alice et Bob utilise la même clé symétrique, la signature du message pourra être faite avec une fonction de hachage qui utilise la clé symétrique en paramêtre.  
Ainsi la vérification de l'intégité des message sera plus simple.

### Compteur

Pour éviter les attaque de répétition, Alice et Bob vont en plus utilisé un compteur qu'ils vont incrémenter à chaque nouveau message, compteur qu'ils s'envoient.

### Fin de la communication

Pour confirmer la fin de la communication, Alice ou Bob va envoyer un message `DONE` qui attendra un message `OK` comme réponse.  
Cela permettra d'être sur que Alice et Bob ont bien supprimé leurs clé symétrique a la fin de la communication.

### Schéma de notre Protocole

sX(m) : signature de m avec la clé privée de X

kX(m) : chiffrement de m avec la clé publique de X

kXY(m) : chiffrement de m avec la clé symétrique partagé entre X et Y

```
Alice                                           Bob
  |-------------{certificat Alice}-------------->|
  |                                              |
  |<-----{certificat Bob, certificat Alice}------|
  |                                              |
  |---------{sA(hash(p, g)), kB(p, g)}---------->|
  |                                              |
  |<-----{g^b mod p, signature(g^b mod p)}-------|
  |                                              |
  |------{g^a mod p, signature(g^a mod p)}------>|    
  |                                              |
  |<-----------------{kAB(ok)}-------------------|
  |                                              |
  |<-----------------{kAB(m)}------------------->|
```

1. Alice -> Bob : certificat Alice
2. Bob -> Alice : certificat Bob, certificat Alice
3. Alice -> Bob : sA(hash(g, p)), kB(g, p)
4. Bob -> Alice : g^b mod p, sB(g^b mod p)
5. Alice -> Bob : g^a mod p, sA(g^a mod p)
6. Bob -> Alice : kAB(ok)

## Fontionnemnt Application

Pour simplifier, nous avons décidé de représenter le serveur et le client sous forme de dossiers, où l'on peut retrouver leurs certificats et leurs clés RSA.  
Pour générer le certificat ainsi que les clés RSA, nous avons utilisé OpenSSL et avons considéré que les certificats étaient autosignés (mais nous avons tout de même implémenté une fonction de vérification très sérieuse et précise du certificat).
```bash
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
openssl rsa -in key.pem -outform PEM -pubout -out public.pem
```
Pour pouvoir utiliser l'application maintenant, il faut ouvrir deux terminaux, un dans le dossier du serveur et un dans celui du client. Une fois dans le dossier, on lance respectivement les commandes pour le serveur en premier, puis pour le client :
```bash
python3 ../app.py --server --debug-level 2
```
```bash
python3 ../app.py --client --debug-level 2
```
PS : Nous sommes dans un environnement Python avec le package PyCryptodome installé.  
Mémo des commandes pour lancer l'environnement Python depuis les dossiers serveur et client :
```
source ../python_venv/bin/activate
deactivate
``` 
  
Une fois lancé, toutes les vérifications ainsi que la création des clés symétriques se font automatiquement.  
Ici, on assume que le serveur et le client ont indiqué le chemin vers leurs clés publiques au préalable, pour qu'ils n'aient rien à indiquer avant la connexion.


## Limite de notre implémentation

Pour Diffie-Hellman, on n'a pas trouvé de base de données en ligne pour obtenir des couples de nombres premiers et de générateurs. On a donc utilisé ChatGPT pour nous en générer des assez grands, mais cela reste tout de même très peu sécurisé. Notre liste ne contient qu'une dizaine de couples avec des nombres premiers très proches, et les générateurs sont petits. Mais le but ici est juste d'illustrer le fonctionnement de Diffie-Hellman.  

Il n'y a aucune vérification de certificat dans notre application. Ici, on n'est pas passé par une autorité de certification pour rester simple : on ne fait qu'une simulation avec des certificats autosignés que l'on assume valides.  

Dans notre application, une fois Diffie-Hellman terminé, on stocke les clés symétriques dans un fichier en clair, ce qui n'est pas sécurisé.  
Aussi, si la communication est interrompue de manière imprévue (une erreur ou autre), les fichiers contenant les clés RSA publiques et les clés AES ne sont pas supprimés.  

Nous avons également assumé que les messages envoyés ne sont pas trop longs, car nous ne vérifions pas si le message dépasse 1024 octets ou non. Si le message est trop long, il sera alors coupé, et il n'y aura pas de fin de message.  

## Détail app

Pour la clé AES et la clé HMAC (pour signer les messages), on a hashé le nombre obtenu avec Diffie-Hellman (avec SHA-256). Une fois hashé, on obtient un digest de 32 octets, ce qui va nous servir pour faire les deux clés, car on a besoin de deux clés de 16 octets. Donc les 16 premiers octets du digest servent pour la clé AES et les 16 derniers pour la clé HMAC.  

Pour l'envoi du certificat, on n'a pas pu le faire en une seule fois, car il est trop grand. On a donc dû couper le certificat en plusieurs bouts. Ici, on a décidé de le couper en bouts de 128 octets, comme ça, une fois hashé, chaque bout fait 256 octets, ce qui nous permet de savoir exactement combien d'octets le récepteur doit récupérer pour chaque trame. Pour indiquer la fin du message, on ajoute un "END" à la fin.

## Source 
- https://rya-sge.github.io/access-denied/2021/10/28/diffie-hellman-python/
- https://www.pycryptodome.org/src/introduction
