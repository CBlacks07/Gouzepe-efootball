const { contextBridge, ipcRenderer } = require('electron');

// Exposer des APIs sécurisées au renderer process
contextBridge.exposeInMainWorld('electronAPI', {
  // Informations sur l'application
  getAppVersion: () => process.versions.electron,
  platform: process.platform,

  // Fonctions utiles pour l'application
  isElectron: true,

  // Événements IPC (si nécessaire plus tard)
  on: (channel, callback) => {
    // Whitelist des canaux autorisés
    const validChannels = ['app-update', 'notification'];
    if (validChannels.includes(channel)) {
      ipcRenderer.on(channel, (event, ...args) => callback(...args));
    }
  },

  send: (channel, data) => {
    // Whitelist des canaux autorisés
    const validChannels = ['app-message'];
    if (validChannels.includes(channel)) {
      ipcRenderer.send(channel, data);
    }
  }
});

// Injecter des informations utiles pour l'application
window.addEventListener('DOMContentLoaded', () => {
  console.log('Application GOUZEPE eFOOT - Version Desktop');
  console.log('Electron:', process.versions.electron);
  console.log('Chrome:', process.versions.chrome);
  console.log('Node:', process.versions.node);
});
