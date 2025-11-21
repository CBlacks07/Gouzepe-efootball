# Icônes de l'application

## Icônes requises

Pour que l'application fonctionne correctement sur toutes les plateformes, vous devez fournir les icônes suivantes :

### Windows
- `icon.ico` - Fichier ICO multi-résolution (16x16, 32x32, 48x48, 256x256)

### macOS
- `icon.icns` - Fichier ICNS (contient plusieurs tailles : 16x16, 32x32, 128x128, 256x256, 512x512, 1024x1024)

### Linux
- `icon.png` - Image PNG de 512x512 pixels minimum

## Génération des icônes

### Option 1 : Utiliser un outil en ligne

1. Créez une image PNG de 1024x1024 pixels avec votre logo
2. Utilisez un convertisseur en ligne comme :
   - https://www.icoconverter.com/ (pour .ico)
   - https://cloudconvert.com/png-to-icns (pour .icns)
   - Ou gardez le PNG pour Linux

### Option 2 : Utiliser electron-icon-builder

```bash
npm install -g electron-icon-builder

# Depuis la racine du projet, avec une image source de 1024x1024
electron-icon-builder --input=./source-icon.png --output=./electron/icons
```

### Option 3 : Créer manuellement avec ImageMagick

```bash
# Pour Windows (ICO)
convert source-icon.png -define icon:auto-resize=256,128,96,64,48,32,16 icon.ico

# Pour macOS (ICNS) - utiliser iconutil sur macOS
mkdir icon.iconset
sips -z 16 16     source-icon.png --out icon.iconset/icon_16x16.png
sips -z 32 32     source-icon.png --out icon.iconset/icon_16x16@2x.png
# ... répéter pour toutes les tailles
iconutil -c icns icon.iconset

# Pour Linux (PNG)
convert source-icon.png -resize 512x512 icon.png
```

## Image temporaire

Pour le développement, vous pouvez utiliser n'importe quelle image PNG de 512x512 pixels.
L'application fonctionnera sans icônes, mais aura l'icône par défaut d'Electron.

## Recommandations

- **Format source** : PNG avec transparence (alpha channel)
- **Taille source** : 1024x1024 pixels minimum
- **Design** : Simple, reconnaissable même en petite taille
- **Couleurs** : Contraste élevé pour une bonne visibilité

## Exemple de logo GOUZEPE eFOOT

Pour votre application de tournois eFOOTBALL, vous pourriez créer un logo avec :
- Un ballon de football stylisé
- Les lettres "GEF" ou "GOUZEPE"
- Des couleurs vives (vert, bleu, rouge)
- Un style moderne et gaming
