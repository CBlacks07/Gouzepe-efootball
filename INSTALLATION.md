# Guide d'installation - GOUZEPE eFOOT Desktop

## ⚠️ Important

L'installation des dépendances Electron peut échouer dans certains environnements avec des restrictions réseau. Si vous rencontrez des erreurs 403 lors de l'installation, suivez ces étapes sur votre machine locale.

## Installation sur votre machine locale

### Prérequis
- Node.js >= 18.0.0 ([Télécharger Node.js](https://nodejs.org/))
- npm (inclus avec Node.js)
- PostgreSQL ([Télécharger PostgreSQL](https://www.postgresql.org/download/))
- Git (pour cloner le projet)

### Étapes d'installation

1. **Cloner le projet** (si ce n'est pas déjà fait)
   ```bash
   git clone <votre-repo-url>
   cd Gouzepe-efootball
   ```

2. **Installer les dépendances principales**
   ```bash
   npm install
   ```

   Si vous rencontrez des erreurs avec Electron, essayez :
   ```bash
   # Option 1 : Utiliser un miroir alternatif
   npm config set electron_mirror https://npmmirror.com/mirrors/electron/
   npm install

   # Option 2 : Installer manuellement Electron
   npm install electron@28.0.0 --save-dev
   npm install electron-builder@24.9.1 --save-dev
   npm install electron-squirrel-startup@1.0.0 --save
   ```

3. **Installer les dépendances de l'API**
   ```bash
   cd api
   npm install
   cd ..
   ```

4. **Configurer PostgreSQL**

   a. Créer la base de données :
   ```sql
   CREATE DATABASE gouzepe_efoot;
   ```

   b. Créer le fichier `.env` dans le dossier `api/` :
   ```env
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=gouzepe_efoot
   DB_USER=votre_utilisateur_postgres
   DB_PASSWORD=votre_mot_de_passe
   PORT=3000
   JWT_SECRET=votre_secret_jwt_aleatoire_securise
   ```

5. **Initialiser la base de données**
   ```bash
   cd api
   npm run db:test
   ```

6. **Créer un compte administrateur** (optionnel)
   ```bash
   cd api
   npm run seed:admin
   ```

## Lancer l'application

### Mode développement
```bash
npm run dev
```
Cette commande lance l'application Electron avec le serveur API intégré.

### Compiler l'application

#### Pour Windows
```bash
npm run build:win
```
Génère un installateur dans `dist/`

#### Pour macOS
```bash
npm run build:mac
```
Génère un fichier DMG dans `dist/`

#### Pour Linux
```bash
npm run build:linux
```
Génère AppImage et DEB dans `dist/`

## Structure de l'application

```
Gouzepe-efootball/
├── electron/              # Application Electron
│   ├── main.js           # Processus principal
│   ├── preload.js        # Sécurité
│   └── icons/            # Icônes (à personnaliser)
├── api/                  # Backend Node.js
│   ├── server.js
│   ├── package.json
│   └── .env             # Configuration (à créer)
├── web/                  # Frontend
│   ├── login.html
│   └── ...
└── package.json          # Configuration Electron
```

## Fonctionnement

L'application desktop GOUZEPE eFOOT fonctionne ainsi :

1. **Au démarrage** : Le processus principal Electron (`electron/main.js`) :
   - Lance automatiquement le serveur API Node.js
   - Crée une fenêtre de l'application
   - Charge l'interface web

2. **En cours d'exécution** :
   - Le serveur API tourne en arrière-plan sur le port 3000
   - L'interface web communique avec l'API via Socket.IO et HTTP
   - Toutes les fonctionnalités web sont conservées

3. **À la fermeture** :
   - Le serveur API est automatiquement arrêté
   - Toutes les ressources sont libérées

## Dépannage

### Erreur : Cannot find module 'electron'
```bash
npm install electron --save-dev
```

### Erreur : ECONNREFUSED lors du démarrage
- Vérifiez que PostgreSQL est en cours d'exécution
- Vérifiez les paramètres dans `api/.env`
- Vérifiez que le port 3000 n'est pas déjà utilisé

### Erreur : Database connection failed
```bash
# Vérifier que PostgreSQL est démarré
# Windows :
pg_ctl status

# macOS/Linux :
sudo systemctl status postgresql
# ou
pg_ctl status -D /usr/local/var/postgres
```

### L'application démarre mais affiche une page blanche
- Ouvrez les outils de développement (Ctrl+Shift+I)
- Vérifiez la console pour les erreurs
- Assurez-vous que le serveur API a bien démarré

## Icônes personnalisées

Pour personnaliser les icônes de l'application, consultez `electron/icons/README.md`.

Vous devrez fournir :
- `icon.png` (512x512) pour Linux
- `icon.ico` (multi-résolution) pour Windows
- `icon.icns` pour macOS

## Support

Pour toute question :
1. Vérifiez ce guide d'installation
2. Consultez `README-DESKTOP.md`
3. Vérifiez les logs de l'application
4. Contactez l'équipe de développement

## Prochaines étapes

Une fois l'application installée et fonctionnelle :
- Personnalisez les icônes
- Configurez les utilisateurs
- Créez des tournois
- Testez toutes les fonctionnalités

Bon développement ! ⚽🎮
