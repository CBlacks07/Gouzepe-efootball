# Gouzepe-efootball

Application web de gestion de compétition eFootball avec classements, duels, et gestion de journées en temps réel.

## Technologies

- **Backend**: Node.js + Express
- **Base de données**: PostgreSQL
- **Temps réel**: Socket.IO
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Desktop**: Electron (application de bureau)
- **Authentification**: JWT (JSON Web Tokens)
- **Sécurité**: Helmet.js, CORS

## Fonctionnalités

### Pour les membres
- 📊 Visualisation du classement général
- 🎮 Consultation des résultats de duels
- 👤 Panneau personnel avec statistiques
- 🔔 Notifications en temps réel des changements de score

### Pour les administrateurs
- 🏠 Saisie des scores de journée en temps réel
- 👥 Gestion des joueurs (ajout, modification, suppression)
- 🔐 Gestion des utilisateurs et autorisations
- 💾 Système de brouillon automatique (sauvegarde toutes les 15 secondes)
- 🏆 Gestion des champions et barrages

## Installation

### Prérequis
- Node.js (v14 ou supérieur)
- PostgreSQL (v12 ou supérieur)
- npm ou yarn

### 1. Cloner le projet
```bash
git clone <url-du-repo>
cd Gouzepe-efootball
```

### 2. Configuration de la base de données
```bash
# Créer la base de données
createdb -U postgres EFOOTBALL

# Importer le schéma
psql -U postgres -d EFOOTBALL -f db/schema.sql
```

**Configuration par défaut**:
- Database: `EFOOTBALL`
- User: `postgres`
- Password: `Admin123`
- Host: `localhost`
- Port: `5432`

### 3. Installation des dépendances API
```bash
cd api
npm install
```

### 4. Lancement du serveur API
```bash
cd api
npm start
# ou en mode développement avec nodemon
npm run dev
```

Le serveur démarrera sur le port **3005** et sera accessible sur toutes les interfaces réseau (0.0.0.0).

### 5. Accès à l'application web
Ouvrez votre navigateur à l'adresse:
```
http://localhost:3005
```

## Application de bureau (Electron)

L'application peut être lancée en mode bureau avec Electron.

### Installation des dépendances Electron
```bash
npm install
```

### Lancement en mode développement
```bash
npm start
```

### Build pour production
```bash
# Windows
npm run build:win

# Linux
npm run build:linux

# macOS
npm run build:mac
```

Les exécutables seront générés dans le dossier `dist/`.

## Structure du projet

```
Gouzepe-efootball/
├── api/              # Backend Node.js
│   ├── server.js     # Point d'entrée du serveur
│   └── ...
├── db/               # Scripts de base de données
│   ├── schema.sql
│   └── migration_*.sql
├── web/              # Frontend (pages HTML/CSS/JS)
│   ├── Accueil.html
│   ├── Classement-general.html
│   ├── Panel-Membre.html
│   ├── Admin-Joueurs.html
│   ├── Admin-Utilisateurs.html
│   └── Duel.html
├── assets/           # Ressources (images, icônes)
├── main.js           # Process principal Electron
├── preload.js        # Script de préchargement Electron
└── package.json      # Configuration du projet
```

## Configuration réseau

L'application est configurée pour être accessible:
- **Localement**: http://localhost:3005
- **Sur le réseau local**: http://[votre-ip-locale]:3005

Le serveur écoute sur `0.0.0.0` pour permettre les connexions depuis n'importe quelle interface réseau.

## Sécurité

- Authentification JWT avec tokens sécurisés
- Protection CORS configurée
- Helmet.js pour les en-têtes de sécurité HTTP
- Hachage des mots de passe avec bcrypt
- Protection contre les injections SQL (requêtes paramétrées)
- Validation des entrées utilisateur

## Déconnexion sécurisée

Lors de la déconnexion, l'application effectue un nettoyage complet:
- Appel API de déconnexion
- Effacement du localStorage (sauf préférences de thème)
- Effacement du sessionStorage
- Nettoyage des caches du service worker
- Sauvegarde automatique des brouillons en cours (administrateurs)

## Développement

### Variables d'environnement
Créez un fichier `.env` dans le dossier `api/` avec:
```env
PORT=3005
DB_HOST=localhost
DB_PORT=5432
DB_NAME=EFOOTBALL
DB_USER=postgres
DB_PASSWORD=Admin123
JWT_SECRET=votre_secret_jwt_ici
```

### Migrations de base de données
Les scripts de migration se trouvent dans `db/`. Consultez `db/README_MIGRATION.md` pour plus de détails.

## Support et Contact

**Application développée par OPS CORPORATION**
- Email: cmaathey@gmail.com

Pour toute question, suggestion ou signalement de bug, contactez-nous à l'adresse ci-dessus.

## Licence

Tous droits réservés - OPS CORPORATION
