const { app, BrowserWindow, Menu, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

// Gérer le démarrage automatique sur Windows
if (require('electron-squirrel-startup')) {
  app.quit();
}

let mainWindow;
let apiProcess;
let serverNetworkInfo = null;

const API_PORT = process.env.API_PORT || 3005;
const API_HOST = process.env.API_HOST || '0.0.0.0'; // 0.0.0.0 pour réseau, localhost pour local uniquement
const API_URL = `http://localhost:${API_PORT}`;

// Fonction pour obtenir les IPs locales
function getLocalIPs() {
  const os = require('os');
  const networkInterfaces = os.networkInterfaces();
  const ips = [];

  Object.keys(networkInterfaces).forEach(interfaceName => {
    networkInterfaces[interfaceName].forEach(iface => {
      if (iface.family === 'IPv4' && !iface.internal) {
        ips.push(iface.address);
      }
    });
  });

  return ips;
}

// Fonction pour démarrer le serveur API
function startApiServer() {
  return new Promise((resolve, reject) => {
    console.log('Démarrage du serveur API...');

    // Déterminer le chemin du serveur selon l'environnement
    const isDev = process.argv.includes('--dev');
    const apiPath = isDev
      ? path.join(__dirname, '../api')
      : path.join(process.resourcesPath, 'api');

    const serverPath = path.join(apiPath, 'server.js');

    // Vérifier que le fichier existe
    if (!fs.existsSync(serverPath)) {
      reject(new Error(`Serveur API non trouvé: ${serverPath}`));
      return;
    }

    // Lancer le processus Node.js avec HOST et PORT configurés
    apiProcess = spawn('node', [serverPath], {
      cwd: apiPath,
      env: {
        ...process.env,
        NODE_ENV: isDev ? 'development' : 'production',
        PORT: API_PORT.toString(),
        HOST: API_HOST
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    apiProcess.stdout.on('data', (data) => {
      const output = data.toString().trim();
      console.log(`[API] ${output}`);

      // Vérifier si le serveur a démarré
      if (output.includes('API OK') || output.includes('démarré') || output.includes('listening')) {
        // Capturer les informations réseau
        if (API_HOST === '0.0.0.0') {
          const localIPs = getLocalIPs();
          serverNetworkInfo = {
            localhost: `http://localhost:${API_PORT}`,
            networkIPs: localIPs.map(ip => `http://${ip}:${API_PORT}`)
          };
        }
        resolve();
      }
    });

    apiProcess.stderr.on('data', (data) => {
      console.error(`[API Error] ${data.toString().trim()}`);
    });

    apiProcess.on('error', (error) => {
      console.error('Erreur lors du démarrage du serveur API:', error);
      reject(error);
    });

    apiProcess.on('close', (code) => {
      console.log(`Serveur API arrêté avec le code ${code}`);
    });

    // Timeout de 10 secondes pour le démarrage
    setTimeout(() => {
      if (apiProcess && !apiProcess.killed) {
        resolve(); // On considère que c'est bon après 10s
      }
    }, 10000);
  });
}

// Fonction pour arrêter le serveur API
function stopApiServer() {
  if (apiProcess && !apiProcess.killed) {
    console.log('Arrêt du serveur API...');
    apiProcess.kill();
    apiProcess = null;
  }
}

// Fonction pour créer la fenêtre principale
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 768,
    icon: path.join(__dirname, 'icons/icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: true
    },
    autoHideMenuBar: false,
    show: false // Ne pas afficher avant que la fenêtre soit prête
  });

  // Créer le menu de l'application
  const menuTemplate = [
    {
      label: 'Fichier',
      submenu: [
        {
          label: 'Actualiser',
          accelerator: 'CmdOrCtrl+R',
          click: () => mainWindow.reload()
        },
        { type: 'separator' },
        {
          label: 'Quitter',
          accelerator: 'CmdOrCtrl+Q',
          click: () => app.quit()
        }
      ]
    },
    {
      label: 'Affichage',
      submenu: [
        {
          label: 'Plein écran',
          accelerator: 'F11',
          click: () => {
            mainWindow.setFullScreen(!mainWindow.isFullScreen());
          }
        },
        {
          label: 'Outils de développement',
          accelerator: 'CmdOrCtrl+Shift+I',
          click: () => mainWindow.webContents.openDevTools()
        }
      ]
    },
    {
      label: 'Réseau',
      submenu: [
        {
          label: 'Afficher les adresses réseau',
          click: () => {
            if (serverNetworkInfo && serverNetworkInfo.networkIPs.length > 0) {
              const urls = [
                `Local : ${serverNetworkInfo.localhost}`,
                '',
                'Réseau local (autres appareils) :',
                ...serverNetworkInfo.networkIPs.map(ip => `  • ${ip}`)
              ].join('\n');

              dialog.showMessageBox(mainWindow, {
                type: 'info',
                title: 'Adresses d\'accès au serveur',
                message: 'Serveur accessible sur le réseau',
                detail: `${urls}\n\nLes autres appareils sur le même réseau WiFi peuvent se connecter avec ces URLs.`,
                buttons: ['Copier', 'Fermer'],
                defaultId: 1
              }).then(result => {
                if (result.response === 0) {
                  // Copier dans le presse-papier
                  require('electron').clipboard.writeText(serverNetworkInfo.networkIPs[0]);
                }
              });
            } else {
              dialog.showMessageBox(mainWindow, {
                type: 'info',
                title: 'Mode local uniquement',
                message: 'Serveur en mode local',
                detail: 'Le serveur est configuré en mode local uniquement.\n\nPour activer l\'accès réseau, configurez la variable d\'environnement API_HOST=0.0.0.0',
                buttons: ['OK']
              });
            }
          }
        }
      ]
    },
    {
      label: 'Aide',
      submenu: [
        {
          label: 'À propos',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'À propos de GOUZEPE eFOOT',
              message: 'GOUZEPE eFOOT',
              detail: `Version: ${app.getVersion()}\n\nApplication de gestion de tournois eFOOTBALL`,
              buttons: ['OK']
            });
          }
        }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(menuTemplate);
  Menu.setApplicationMenu(menu);

  // Charger l'application
  const isDev = process.argv.includes('--dev');
  const startUrl = isDev
    ? `${API_URL}/web/login.html`
    : `file://${path.join(__dirname, '../web/login.html')}`;

  mainWindow.loadURL(startUrl);

  // Afficher la fenêtre quand elle est prête
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  // Ouvrir les liens externes dans le navigateur
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http') && !url.includes('localhost')) {
      require('electron').shell.openExternal(url);
      return { action: 'deny' };
    }
    return { action: 'allow' };
  });

  // Gérer la fermeture
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Événement: Application prête
app.whenReady().then(async () => {
  try {
    // Démarrer le serveur API
    await startApiServer();
    console.log('Serveur API démarré avec succès');

    // Créer la fenêtre
    createWindow();

  } catch (error) {
    console.error('Erreur lors du démarrage:', error);

    dialog.showErrorBox(
      'Erreur de démarrage',
      `Impossible de démarrer le serveur API:\n\n${error.message}\n\nVérifiez que PostgreSQL est installé et configuré.`
    );

    app.quit();
  }
});

// Événement: Toutes les fenêtres sont fermées
app.on('window-all-closed', () => {
  stopApiServer();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Événement: L'application est activée (macOS)
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// Événement: L'application va quitter
app.on('before-quit', () => {
  stopApiServer();
});

// Gérer les erreurs non capturées
process.on('uncaughtException', (error) => {
  console.error('Erreur non capturée:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Promesse rejetée non gérée:', promise, 'raison:', reason);
});
