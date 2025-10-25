/* ==========================================
   GOUZEPE eFOOTBALL - PWA Initialization
   Service Worker Registration & Install Prompt
   ========================================== */

(function() {
  'use strict';

  // === ENREGISTREMENT SERVICE WORKER ===
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', async () => {
      try {
        const registration = await navigator.serviceWorker.register('/web/service-worker.js', {
          scope: '/web/'
        });

        console.log('[PWA] Service Worker enregistré:', registration.scope);

        // Vérifier les mises à jour toutes les heures
        setInterval(() => {
          registration.update();
        }, 60 * 60 * 1000);

        // Écouter les updates
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              // Nouvelle version disponible
              showUpdateNotification();
            }
          });
        });

      } catch (error) {
        console.warn('[PWA] Erreur Service Worker:', error);
      }
    });
  }

  // === PROMPT D'INSTALLATION ===
  let deferredPrompt;
  const installContainer = createInstallPrompt();

  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;

    // Vérifier si déjà installé ou prompt déjà refusé
    const dismissed = localStorage.getItem('pwa-install-dismissed');
    const standalone = window.matchMedia('(display-mode: standalone)').matches;

    if (!dismissed && !standalone) {
      setTimeout(() => {
        installContainer.style.display = 'block';
        installContainer.classList.add('slide-in');
      }, 3000); // Attendre 3s avant d'afficher
    }
  });

  // Bouton installer
  const installBtn = installContainer.querySelector('#pwa-install-btn');
  installBtn?.addEventListener('click', async () => {
    if (!deferredPrompt) return;

    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;

    console.log('[PWA] Installation:', outcome);

    if (outcome === 'accepted') {
      installContainer.style.display = 'none';
    }

    deferredPrompt = null;
  });

  // Bouton fermer
  const closeBtn = installContainer.querySelector('#pwa-install-close');
  closeBtn?.addEventListener('click', () => {
    installContainer.classList.add('slide-out');
    setTimeout(() => {
      installContainer.style.display = 'none';
    }, 300);
    localStorage.setItem('pwa-install-dismissed', Date.now());
  });

  // Détecter si installé
  window.addEventListener('appinstalled', () => {
    console.log('[PWA] App installée avec succès !');
    installContainer.style.display = 'none';
    localStorage.setItem('pwa-installed', 'true');
  });

  // Détecter si lancé en mode standalone
  if (window.matchMedia('(display-mode: standalone)').matches) {
    console.log('[PWA] Mode standalone activé');
    document.documentElement.classList.add('pwa-standalone');
  }

  // === FONCTIONS UTILITAIRES ===
  function createInstallPrompt() {
    const container = document.createElement('div');
    container.id = 'pwa-install-prompt';
    container.style.cssText = `
      display: none;
      position: fixed;
      bottom: 20px;
      left: 50%;
      transform: translateX(-50%);
      max-width: 90vw;
      width: 400px;
      background: linear-gradient(135deg, #16a34a 0%, #15803d 100%);
      color: white;
      padding: 18px 20px;
      border-radius: 16px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      z-index: 9999;
      font-family: system-ui, -apple-system, sans-serif;
      animation: slideUp 0.3s ease-out;
    `;

    container.innerHTML = `
      <div style="display: flex; align-items: center; gap: 12px;">
        <div style="font-size: 32px;">⚽</div>
        <div style="flex: 1;">
          <div style="font-weight: 700; font-size: 16px; margin-bottom: 4px;">
            Installer GOUZEPE
          </div>
          <div style="font-size: 13px; opacity: 0.95;">
            Accès rapide depuis votre écran d'accueil
          </div>
        </div>
        <button id="pwa-install-close" style="
          background: rgba(255,255,255,0.2);
          border: none;
          color: white;
          width: 28px;
          height: 28px;
          border-radius: 50%;
          cursor: pointer;
          font-size: 18px;
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
        ">×</button>
      </div>
      <button id="pwa-install-btn" style="
        width: 100%;
        margin-top: 14px;
        padding: 12px;
        background: white;
        color: #16a34a;
        border: none;
        border-radius: 12px;
        font-weight: 700;
        font-size: 15px;
        cursor: pointer;
        transition: transform 0.1s ease;
      ">
        📲 Installer l'application
      </button>
    `;

    document.body.appendChild(container);

    // Ajouter les styles d'animation
    const style = document.createElement('style');
    style.textContent = `
      @keyframes slideUp {
        from {
          transform: translateX(-50%) translateY(100px);
          opacity: 0;
        }
        to {
          transform: translateX(-50%) translateY(0);
          opacity: 1;
        }
      }
      #pwa-install-prompt.slide-out {
        animation: slideDown 0.3s ease-out forwards;
      }
      @keyframes slideDown {
        to {
          transform: translateX(-50%) translateY(100px);
          opacity: 0;
        }
      }
      #pwa-install-btn:hover {
        transform: scale(1.02);
      }
      #pwa-install-btn:active {
        transform: scale(0.98);
      }
    `;
    document.head.appendChild(style);

    return container;
  }

  function showUpdateNotification() {
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      max-width: 300px;
      background: #3b82f6;
      color: white;
      padding: 16px;
      border-radius: 12px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.2);
      z-index: 9999;
      font-family: system-ui;
      animation: slideIn 0.3s ease-out;
    `;

    notification.innerHTML = `
      <div style="font-weight: 700; margin-bottom: 4px;">Mise à jour disponible</div>
      <div style="font-size: 14px; opacity: 0.95; margin-bottom: 12px;">
        Une nouvelle version est prête
      </div>
      <button onclick="location.reload()" style="
        width: 100%;
        padding: 10px;
        background: white;
        color: #3b82f6;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        cursor: pointer;
      ">
        Recharger
      </button>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease-out forwards';
      setTimeout(() => notification.remove(), 300);
    }, 10000);
  }

  // === DÉTECTION DE CONNEXION ===
  window.addEventListener('online', () => {
    console.log('[PWA] Connexion rétablie');
    showToast('✅ Connexion rétablie', 'success');
  });

  window.addEventListener('offline', () => {
    console.log('[PWA] Hors ligne');
    showToast('⚠️ Mode hors ligne', 'warning');
  });

  function showToast(message, type = 'info') {
    const colors = {
      success: '#16a34a',
      warning: '#f59e0b',
      error: '#ef4444',
      info: '#3b82f6'
    };

    const toast = document.createElement('div');
    toast.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: ${colors[type]};
      color: white;
      padding: 12px 18px;
      border-radius: 10px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.2);
      z-index: 9998;
      font-family: system-ui;
      font-size: 14px;
      font-weight: 600;
      animation: slideIn 0.3s ease-out;
    `;
    toast.textContent = message;

    document.body.appendChild(toast);

    setTimeout(() => {
      toast.style.animation = 'slideOut 0.3s ease-out forwards';
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }

  // === PARTAGE API ===
  window.shareContent = async function(title, text, url) {
    if (navigator.share) {
      try {
        await navigator.share({ title, text, url });
        console.log('[PWA] Contenu partagé');
      } catch (err) {
        if (err.name !== 'AbortError') {
          console.warn('[PWA] Erreur partage:', err);
        }
      }
    } else {
      // Fallback: copier dans presse-papier
      try {
        await navigator.clipboard.writeText(url);
        showToast('✅ Lien copié', 'success');
      } catch (err) {
        console.warn('[PWA] Clipboard non disponible');
      }
    }
  };

})();
