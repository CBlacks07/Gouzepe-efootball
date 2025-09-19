# Déploiement sur Render — GOUZEPE

Ce dépôt contient une API Node/Express (`/api`) et un site statique (`/web`).  
Le fichier **render.yaml** provisionne automatiquement :

- un **PostgreSQL** (`gouzepe-db`)
- un **service web Node** pour l'API (`gouzepe-api`)
- un **site statique** pour le front (`gouzepe-static`)

## Étapes rapides

1. **Commit & push** `render.yaml` à la racine du repo.
2. Dans le **Dashboard Render**, crée un *Blueprint* depuis ce repo (New ➜ Blueprint).  
3. Laisse Render créer les 3 ressources (DB, API, Static).

### Variables d'environnement côté API
- `DATABASE_URL` — injecté automatiquement depuis la DB Render (privée).
- `PGSSL=true` — force SSL pg en prod.
- `JWT_SECRET` — généré automatiquement (ou remplace-le par ta propre valeur).
- `CORS_ORIGIN` — **IMPORTANT** : autorise l'origine de ton site statique.  
  Par défaut: `https://gouzepe-static.onrender.com` + localhost (dev).  
  Ajoute aussi ton domaine personnalisé si tu en utilises un (ex: `https://gouzepe.app`).
- `TEAM_KEY_LEN`, `EMAIL_DOMAIN` — options facultatives pour l’app.

### Santé & zéro-downtime
- Le service API expose `GET /health` et `GET /healthz`.
- Dans `render.yaml`, `healthCheckPath: /health` est déjà configuré.

### Nommage des services
Le front tente d’**auto‑détecter l’API** en remplaçant `-static` par `-api` sur le domaine Render.  
Garde les noms par défaut (**gouzepe-static** et **gouzepe-api**) pour que ça marche sans config supplémentaire.

> Si tu changes les noms, pense à définir manuellement l’API dans le navigateur :
>
> Ouvre la console et tape :
>
> ```js
> localStorage.setItem('efoot.api','https://gouzepe-api.onrender.com');
> location.reload();
> ```

### Création d’un admin
Optionnel mais pratique : créer un admin via la console Render (Shell) du service **gouzepe-api** :

```bash
ADMIN_EMAIL="admin@gouzepe.local" ADMIN_PASSWORD="change-moi" node create_admin.js
```

### Postgres
La **DB est privée** et accessible depuis l’API via `DATABASE_URL`.  
Tu peux exporter/importer avec `pg_dump` / `psql` si besoin.

---

## Dépannage rapide

- **CORS** : vérifie que l’URL du site statique figure bien dans `CORS_ORIGIN` (exact match, séparé par des virgules).  
- **Socket.IO** : Render ne passe que par `80/443` derrière un proxy. Pas de port custom côté client.  
- **Racine du site** 404 : le front publie `/web` — la route `/ -> /login.html` est déjà posée.
- **SSL pg** : si erreur `self signed certificate`, garde `PGSSL=true` (ou configure `ssl.rejectUnauthorized=false`).

Bon déploiement 🚀
