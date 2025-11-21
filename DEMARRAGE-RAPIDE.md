# 🚀 Guide de Démarrage Rapide - GOUZEPE eFOOT

## ⚠️ Problème : Le serveur ne démarre pas ou le login ne fonctionne pas

Si vous voyez la page de login mais que la connexion ne fonctionne pas, c'est probablement un problème de **configuration de la base de données**.

## ✅ Solution en 3 étapes

### Étape 1 : Vérifier PostgreSQL

**Vérifiez que PostgreSQL est installé et démarré :**

**Sur Windows :**
1. Ouvrez les Services Windows (`services.msc`)
2. Cherchez "postgresql" dans la liste
3. Le service doit être "En cours d'exécution"
4. Si non, faites un clic droit → Démarrer

**Ou avec pgAdmin :**
1. Lancez pgAdmin 4
2. Si vous pouvez vous connecter à votre serveur PostgreSQL, c'est bon !

### Étape 2 : Créer la base de données

**Ouvrez pgAdmin ou psql et exécutez :**

```sql
CREATE DATABASE "EFOOTBALL";
```

**Ou depuis la ligne de commande Windows :**
```cmd
psql -U postgres -c "CREATE DATABASE EFOOTBALL;"
```

Si psql demande un mot de passe, entrez votre mot de passe PostgreSQL.

### Étape 3 : Configurer la connexion

**Créez le fichier de configuration :**

1. Allez dans le dossier `api/`
2. Créez un fichier nommé `.env` (attention au point au début)
3. Copiez ce contenu dans le fichier :

```env
# Base de données PostgreSQL
PGHOST=localhost
PGPORT=5432
PGDATABASE=EFOOTBALL
PGUSER=postgres
PGPASSWORD=Admin123

# Serveur
PORT=3005
HOST=0.0.0.0

# Sécurité
JWT_SECRET=votre_secret_aleatoire_ici
```

**⚠️ IMPORTANT : Changez `PGPASSWORD`** avec votre vrai mot de passe PostgreSQL !

### Étape 4 : Créer un utilisateur admin

**Une fois la base de données créée et configurée :**

```bash
cd api
node create_admin.js
```

Cela créera un compte admin par défaut.

### Étape 5 : Relancer l'application

```bash
npm run dev
```

## 🔍 Vérification rapide

**Pour tester si PostgreSQL fonctionne :**

```bash
cd api
node test_db.js
```

Si vous voyez "✅ Connexion réussie", c'est bon !

## 📋 Identifiants par défaut

Après avoir exécuté `create_admin.js`, vous pouvez vous connecter avec :

- **Email :** `admin@gz.local`
- **Mot de passe :** `admin123`

**⚠️ Changez ce mot de passe après la première connexion !**

## ❌ Problèmes courants

### Erreur : "password authentication failed"

**Solution :** Votre mot de passe PostgreSQL dans `.env` est incorrect.

1. Vérifiez le mot de passe que vous avez défini lors de l'installation de PostgreSQL
2. Modifiez `PGPASSWORD` dans `api/.env`

### Erreur : "database EFOOTBALL does not exist"

**Solution :** La base de données n'existe pas.

```sql
CREATE DATABASE "EFOOTBALL";
```

### Erreur : "ECONNREFUSED" ou "connection refused"

**Solution :** PostgreSQL n'est pas démarré.

**Windows :**
- Services → postgresql-x64-XX → Démarrer

**OU** le port PostgreSQL n'est pas 5432 :
- Vérifiez dans pgAdmin : Properties → Connection → Port
- Changez `PGPORT` dans `api/.env` si différent

### PostgreSQL n'est pas installé

**Téléchargez et installez PostgreSQL :**

1. Allez sur https://www.postgresql.org/download/windows/
2. Téléchargez l'installeur
3. Installez avec les options par défaut
4. **Notez le mot de passe** que vous définissez pour l'utilisateur `postgres`
5. Revenez à l'Étape 2 de ce guide

## 📊 Architecture de la base de données

L'application créera automatiquement ces tables au premier démarrage :

- `users` - Utilisateurs et admins
- `players` - Joueurs (avec stats)
- `duels` - Matchs entre joueurs
- `player_stats` - Statistiques des joueurs
- `drafts` - Brouillons de matchs

## 🔐 Variables d'environnement complètes

Voici toutes les variables disponibles dans `api/.env` :

```env
# Base de données
PGHOST=localhost           # Hôte PostgreSQL
PGPORT=5432               # Port PostgreSQL
PGDATABASE=EFOOTBALL      # Nom de la base
PGUSER=postgres           # Utilisateur PostgreSQL
PGPASSWORD=votre_mdp      # Mot de passe PostgreSQL

# OU utiliser une URL de connexion complète :
# DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Serveur
PORT=3005                 # Port du serveur API
HOST=0.0.0.0             # 0.0.0.0 pour réseau, localhost pour local

# Sécurité
JWT_SECRET=secret_aleatoire_long    # Secret pour les tokens JWT

# Email (optionnel)
EMAIL_DOMAIN=gz.local     # Domaine email par défaut

# SSL (optionnel, pour production)
PGSSL=false              # Utiliser SSL pour PostgreSQL
PGSSL_FORCE=false        # Forcer SSL
```

## 🎯 Résumé rapide

```bash
# 1. Créer la base de données
psql -U postgres -c "CREATE DATABASE EFOOTBALL;"

# 2. Créer le fichier api/.env avec vos paramètres

# 3. Créer un admin
cd api
node create_admin.js

# 4. Lancer l'application
cd ..
npm run dev

# 5. Se connecter avec admin@gz.local / admin123
```

## ✅ C'est tout !

Une fois ces étapes complétées, l'application devrait :
- ✅ Démarrer le serveur sur le port 3005
- ✅ Se connecter à PostgreSQL
- ✅ Créer automatiquement les tables
- ✅ Vous permettre de vous connecter

Bon développement ! ⚽🎮
