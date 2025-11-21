# GOUZEPE eFOOT - Application Desktop

## Description

Application desktop pour la gestion de tournois eFOOTBALL. Cette version empaquette le serveur API et l'interface web dans une application native pour Windows, macOS et Linux.

## Prérequis

- **Node.js** >= 18.0.0
- **npm** (inclus avec Node.js)
- **PostgreSQL** (base de données)

## Installation pour le développement

1. **Installer les dépendances principales**
   ```bash
   npm install
   ```

2. **Configurer la base de données**
   - Assurez-vous que PostgreSQL est installé et en cours d'exécution
   - Configurez le fichier `.env` dans le dossier `api/` avec vos informations de connexion :
     ```env
     DB_HOST=localhost
     DB_PORT=5432
     DB_NAME=gouzepe_efoot
     DB_USER=votre_utilisateur
     DB_PASSWORD=votre_mot_de_passe
     PORT=3000
     JWT_SECRET=votre_secret_jwt
     ```

3. **Créer la base de données et les tables**
   ```bash
   cd api
   npm run db:test
   ```

4. **Créer un compte admin (optionnel)**
   ```bash
   cd api
   npm run seed:admin
   ```

## Lancement en mode développement

```bash
npm run dev
```

Cette commande :
- Lance le serveur API sur le port 3000
- Ouvre l'application Electron
- Active le mode développement avec rechargement automatique

## Construction de l'application

### Pour Windows
```bash
npm run build:win
```

Génère un installateur `.exe` dans le dossier `dist/`

### Pour macOS
```bash
npm run build:mac
```

Génère un fichier `.dmg` dans le dossier `dist/`

### Pour Linux
```bash
npm run build:linux
```

Génère des fichiers `.AppImage` et `.deb` dans le dossier `dist/`

### Build pour toutes les plateformes
```bash
npm run build
```

## Structure du projet

```
Gouzepe-efootball/
├── electron/              # Code de l'application Electron
│   ├── main.js           # Processus principal (lance le serveur + fenêtre)
│   ├── preload.js        # Script de sécurité
│   └── icons/            # Icônes de l'application
├── api/                  # Backend Node.js + Express
│   ├── server.js         # Serveur API
│   └── ...               # Routes, contrôleurs, etc.
├── web/                  # Frontend (HTML/CSS/JS)
│   ├── login.html        # Page de connexion
│   └── ...               # Autres pages
├── package.json          # Configuration Electron
└── README-DESKTOP.md     # Ce fichier
```

## Fonctionnalités

✅ **Application native** - Fonctionne hors ligne (une fois la base de données configurée)
✅ **Serveur intégré** - Le serveur API démarre automatiquement avec l'application
✅ **Multi-plateforme** - Windows, macOS, Linux
✅ **Auto-mise à jour** - Mise à jour automatique de l'application (à configurer)
✅ **Notifications système** - Notifications natives du système d'exploitation
✅ **Menu natif** - Menu d'application avec raccourcis clavier

## Raccourcis clavier

- `Ctrl+R` (ou `Cmd+R` sur Mac) : Actualiser l'application
- `F11` : Mode plein écran
- `Ctrl+Shift+I` (ou `Cmd+Shift+I` sur Mac) : Outils de développement
- `Ctrl+Q` (ou `Cmd+Q` sur Mac) : Quitter l'application

## Dépannage

### L'application ne démarre pas

1. Vérifiez que PostgreSQL est en cours d'exécution
2. Vérifiez le fichier `.env` dans `api/`
3. Consultez les logs dans la console

### Erreur de connexion à la base de données

1. Vérifiez les paramètres de connexion dans `api/.env`
2. Assurez-vous que la base de données existe
3. Vérifiez que l'utilisateur PostgreSQL a les bonnes permissions

### Le serveur API ne démarre pas

1. Vérifiez que le port 3000 n'est pas déjà utilisé
2. Installez les dépendances : `cd api && npm install`
3. Testez manuellement : `cd api && npm start`

## Support

Pour toute question ou problème, consultez la documentation ou contactez l'équipe de développement.

## Licence

UNLICENSED - Propriété de GOUZEPE
