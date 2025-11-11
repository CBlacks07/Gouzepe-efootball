# Migration : Permettre la modification d'ID joueur

## Contexte
Cette migration permet de modifier l'ID d'un joueur tout en conservant toutes ses données et statistiques dans l'application.

## Fichiers modifiés

### 1. Base de données
- `db/schema.sql` : Ajout de `ON UPDATE CASCADE` à la contrainte de clé étrangère `users.player_id`
- `db/migration_add_cascade_to_users.sql` : Script de migration à exécuter sur la base existante

### 2. API
- `api/server.js` : Ajout de la route `PUT /admin/players/:oldId` pour mettre à jour un joueur
  - Permet de modifier le `player_id`, `name` et `role`
  - Mise à jour en cascade dans toutes les références :
    - Table `users` (via ON UPDATE CASCADE)
    - Table `champion_result` (via ON UPDATE CASCADE existant)
    - JSONB `matchday.payload` (matchs D1/D2, champions, barrage)
    - JSONB `draft.payload` (brouillons de journées)
    - Map de présence en mémoire

## Exécution de la migration

### Option 1 : Script Node.js (recommandé)
```bash
cd api
node run_migration.js
```

### Option 2 : Connexion directe à PostgreSQL
```bash
psql -U postgres -d efootball -f db/migration_add_cascade_to_users.sql
```

### Option 3 : Via l'outil de votre choix
Exécutez le contenu de `db/migration_add_cascade_to_users.sql` sur votre base de données.

## Utilisation

Une fois la migration exécutée et le serveur API redémarré :

1. Connectez-vous en tant qu'administrateur
2. Allez sur la page "Admin-Joueurs"
3. Cliquez sur "Modifier" pour un joueur
4. Modifiez l'ID dans le champ "ID joueur"
5. Cliquez sur "Sauvegarder"

Un message de confirmation apparaîtra car cette opération modifie toutes les références du joueur dans la base de données.

## Sécurité

- ✅ La modification d'ID nécessite les droits administrateur
- ✅ Vérification que le nouvel ID n'existe pas déjà
- ✅ Message de confirmation avant modification
- ✅ Toutes les références sont mises à jour atomiquement
- ✅ Les données et statistiques du joueur sont conservées

## Notes techniques

La mise à jour de l'ID joueur met à jour :
- ✅ `players.player_id` (clé primaire)
- ✅ `users.player_id` (via CASCADE)
- ✅ `champion_result.champion_id` (via CASCADE existant)
- ✅ Tous les matchs dans `matchday.payload.d1[].p1` et `payload.d1[].p2`
- ✅ Tous les matchs dans `matchday.payload.d2[].p1` et `payload.d2[].p2`
- ✅ Champions dans `matchday.payload.champions.d1.id` et `.d2.id`
- ✅ Gagnant barrage dans `matchday.payload.barrage.winner`
- ✅ Même structure pour les `draft.payload`
- ✅ Map de présence en mémoire `presence.players`
