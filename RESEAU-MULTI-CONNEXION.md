# Guide Multi-Connexion Réseau - GOUZEPE eFOOT

## 🌐 Fonctionnalité Multi-Connexion

L'application desktop GOUZEPE eFOOT permet la **multi-connexion sur le réseau local**. Cela signifie que plusieurs appareils (ordinateurs, tablettes, smartphones) connectés au **même réseau WiFi** peuvent accéder simultanément à l'application.

## 📱 Cas d'utilisation

### Configuration idéale pour un tournoi

1. **Serveur principal** : Un ordinateur exécute l'application Electron (serveur + interface)
2. **Appareils secondaires** : D'autres appareils (tablettes, PC, smartphones) se connectent via navigateur web
3. **Même réseau WiFi** : Tous les appareils doivent être sur le même réseau local

### Exemples concrets

- **Arbitre principal** : Utilise l'ordinateur avec l'application Electron
- **Arbitres secondaires** : Utilisent des tablettes pour saisir les résultats
- **Écran d'affichage** : Un téléviseur connecté affiche les classements en temps réel
- **Joueurs** : Consultent leurs statistiques depuis leur smartphone

## ⚙️ Configuration

### Mode Réseau (Par défaut) ✅

L'application est **configurée par défaut** pour accepter les connexions réseau.

**Variables d'environnement :**
```env
API_HOST=0.0.0.0  # Accepte les connexions réseau (par défaut)
API_PORT=3000     # Port d'écoute (par défaut)
```

### Mode Local uniquement

Si vous souhaitez **désactiver** l'accès réseau et garder l'application en mode local uniquement :

```env
API_HOST=localhost  # Local uniquement
API_PORT=3000
```

## 🚀 Utilisation

### 1. Démarrer l'application desktop

Sur l'ordinateur principal, lancez l'application Electron :

```bash
npm run dev  # Mode développement
# ou
npm start    # Mode production
```

### 2. Obtenir l'adresse réseau

**Méthode 1 : Menu de l'application**
- Cliquez sur le menu **Réseau** → **Afficher les adresses réseau**
- Une fenêtre affiche toutes les URLs accessibles
- Cliquez sur **Copier** pour copier l'URL principale

**Méthode 2 : Console de démarrage**
Au démarrage, le serveur affiche automatiquement :
```
API OK on 0.0.0.0:3000

📡 Serveur accessible depuis le réseau local :
   http://192.168.1.10:3000
   http://192.168.43.1:3000

💡 Les autres appareils peuvent se connecter avec ces URLs
```

### 3. Connecter les autres appareils

Sur les appareils secondaires (tablettes, smartphones, autres PC) :

1. **Assurez-vous d'être sur le même réseau WiFi**
2. **Ouvrez un navigateur web** (Chrome, Firefox, Safari, Edge)
3. **Tapez l'adresse réseau** obtenue à l'étape 2 :
   ```
   http://192.168.1.10:3000
   ```
4. **L'application web s'affiche** exactement comme sur l'ordinateur principal

## 🔒 Sécurité Réseau

### Réseau Local uniquement

- ✅ Les connexions sont **automatiquement limitées au réseau local** (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- ✅ Les connexions depuis Internet sont **automatiquement bloquées**
- ✅ Le serveur n'est **pas accessible depuis l'extérieur** de votre réseau

### Recommandations

1. **Réseau sécurisé** : Utilisez un réseau WiFi avec mot de passe
2. **Réseau privé** : Ne pas utiliser sur un réseau WiFi public
3. **Pare-feu** : Le pare-feu Windows/macOS peut demander l'autorisation au premier lancement

## 🔧 Configuration avancée

### Changer le port d'écoute

Si le port 3000 est déjà utilisé sur votre machine :

**Dans l'application Electron :**
Créez un fichier `.env` à la racine du projet :
```env
API_PORT=8080
API_HOST=0.0.0.0
```

**Dans le dossier api/ :**
Modifiez le fichier `api/.env` :
```env
PORT=8080
HOST=0.0.0.0
```

### Plusieurs instances simultanées

Vous pouvez lancer plusieurs instances de l'application sur des ports différents :

**Instance 1 :**
```env
API_PORT=3000
```

**Instance 2 :**
```env
API_PORT=3001
```

## 🌐 Connexion depuis un navigateur

### URLs de connexion

- **Page de connexion** : `http://[IP]:3000/web/login.html`
- **Accueil** : `http://[IP]:3000/web/Accueil.html`
- **Tournois** : `http://[IP]:3000/web/Tournois.html`
- **Classement** : `http://[IP]:3000/web/Classement-general.html`

### Compatibilité navigateurs

✅ **Compatible avec :**
- Chrome / Edge (recommandé)
- Firefox
- Safari
- Opera
- Navigateurs mobiles (iOS Safari, Chrome Android)

## 🔍 Dépannage

### L'adresse réseau n'est pas affichée

**Problème :** Le menu affiche "Mode local uniquement"

**Solution :**
1. Vérifiez que `API_HOST=0.0.0.0` dans les variables d'environnement
2. Relancez l'application

### Les autres appareils ne peuvent pas se connecter

**Problème :** Erreur "Connexion refusée" ou timeout

**Solutions :**

1. **Vérifiez le réseau WiFi**
   - Tous les appareils sont sur le **même réseau WiFi**
   - Le réseau n'est pas en mode "Isolation client" (common dans les WiFi publics)

2. **Vérifiez le pare-feu**
   ```bash
   # Windows : Autorisez Node.js dans le pare-feu Windows Defender
   # macOS : Système → Sécurité → Pare-feu → Options → Autoriser Node.js
   # Linux : sudo ufw allow 3000/tcp
   ```

3. **Testez la connexion**
   ```bash
   # Sur l'appareil secondaire, testez avec ping
   ping 192.168.1.10
   ```

4. **Vérifiez le port**
   ```bash
   # Sur le serveur, vérifiez que le port est ouvert
   netstat -an | grep 3000
   # ou
   ss -tulpn | grep 3000
   ```

### Socket.IO ne se connecte pas

**Problème :** Les mises à jour en temps réel ne fonctionnent pas

**Solution :**
- Assurez-vous que le port est accessible
- Vérifiez que le CORS est bien configuré (déjà fait automatiquement)
- Rechargez la page avec `Ctrl+Shift+R` (ou `Cmd+Shift+R` sur Mac)

### Adresse IP change fréquemment

**Problème :** L'IP du serveur change à chaque redémarrage

**Solution :** Configurez une IP statique sur votre routeur :
1. Accédez à l'interface de votre routeur (généralement 192.168.1.1 ou 192.168.0.1)
2. Cherchez "DHCP Reservation" ou "IP statique"
3. Associez l'adresse MAC de votre PC à une IP fixe (ex: 192.168.1.100)

## 📊 Performances

### Recommandations

- **Nombre d'appareils** : Jusqu'à 20-30 connexions simultanées sans problème
- **Réseau** : WiFi 5GHz recommandé pour de meilleures performances
- **Serveur** : Ordinateur avec au moins 4GB de RAM

### Optimisation

Pour de meilleures performances avec beaucoup d'utilisateurs :
1. Utilisez un réseau 5GHz au lieu de 2.4GHz
2. Placez le routeur au centre de la zone de couverture
3. Fermez les applications inutiles sur le serveur

## 💡 Astuces

### Partager l'URL rapidement

1. Utilisez le menu **Réseau** → **Afficher les adresses réseau**
2. Cliquez sur **Copier**
3. Partagez l'URL par SMS, email, ou code QR

### Créer un code QR

Pour faciliter la connexion, générez un code QR avec l'URL :
- Utilisez un générateur en ligne : https://www.qr-code-generator.com/
- Entrez l'URL : `http://192.168.1.10:3000`
- Affichez le code QR pour que les joueurs le scannent

### Bookmark sur les appareils

Sur les appareils qui se connectent régulièrement :
1. Ajoutez l'URL aux favoris/signets
2. Sur mobile, ajoutez à l'écran d'accueil
3. Nommez-le "GOUZEPE eFOOT"

## 📱 Mode PWA (Progressive Web App)

L'application web peut être installée comme une app sur les appareils mobiles :

**Sur Android Chrome :**
1. Ouvrez l'URL dans Chrome
2. Menu → "Ajouter à l'écran d'accueil"
3. L'icône apparaît comme une vraie application

**Sur iOS Safari :**
1. Ouvrez l'URL dans Safari
2. Bouton Partager → "Sur l'écran d'accueil"
3. L'app apparaît avec les autres applications

## 🎯 Conclusion

La fonctionnalité multi-connexion permet d'utiliser GOUZEPE eFOOT de manière collaborative sur plusieurs appareils, idéale pour gérer des tournois avec plusieurs arbitres et écrans d'affichage.

**Points clés :**
- ✅ Configuration automatique (mode réseau par défaut)
- ✅ Sécurité réseau local intégrée
- ✅ Menu dédié pour afficher les URLs
- ✅ Compatible tous appareils et navigateurs
- ✅ Synchronisation temps réel via Socket.IO

Pour toute question, consultez la documentation principale ou contactez le support.
