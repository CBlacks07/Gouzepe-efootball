#!/bin/bash
# Script pour générer les icônes PWA à partir du logo

set -e

LOGO="web/assets/fond.png"
OUTPUT_DIR="web/assets/icons"

# Créer le dossier de sortie
mkdir -p "$OUTPUT_DIR"

# Vérifier si ImageMagick est installé
if ! command -v convert &> /dev/null; then
    echo "❌ ImageMagick n'est pas installé."
    echo ""
    echo "📋 OPTION 1: Installer ImageMagick"
    echo "   Ubuntu/Debian: sudo apt-get install imagemagick"
    echo "   macOS: brew install imagemagick"
    echo ""
    echo "📋 OPTION 2: Utiliser un outil en ligne"
    echo "   1. Allez sur: https://realfavicongenerator.net/"
    echo "   2. Uploadez: $LOGO"
    echo "   3. Téléchargez le package d'icônes"
    echo "   4. Extrayez dans: $OUTPUT_DIR/"
    echo ""
    echo "📋 OPTION 3: Utiliser ce script Python"
    echo "   python3 generate-icons.py"
    echo ""
    exit 1
fi

echo "🎨 Génération des icônes PWA..."

# Générer les différentes tailles
sizes=(48 72 96 144 192 512)

for size in "${sizes[@]}"; do
    echo "📐 Création icon-${size}x${size}.png..."
    convert "$LOGO" \
        -resize "${size}x${size}" \
        -background transparent \
        -gravity center \
        -extent "${size}x${size}" \
        "$OUTPUT_DIR/icon-${size}x${size}.png"
done

# Créer l'icône Apple (180x180)
echo "📐 Création apple-touch-icon.png..."
convert "$LOGO" \
    -resize "180x180" \
    -background transparent \
    -gravity center \
    -extent "180x180" \
    "$OUTPUT_DIR/apple-touch-icon.png"

# Créer un favicon.ico
echo "📐 Création favicon.ico..."
convert "$LOGO" \
    -resize "32x32" \
    -background transparent \
    -gravity center \
    -extent "32x32" \
    "$OUTPUT_DIR/favicon.ico"

# Créer une version maskable (avec padding pour les bords arrondis)
echo "📐 Création icon-maskable-512x512.png..."
convert "$LOGO" \
    -resize "410x410" \
    -background "#16a34a" \
    -gravity center \
    -extent "512x512" \
    "$OUTPUT_DIR/icon-maskable-512x512.png"

echo ""
echo "✅ Icônes générées avec succès dans: $OUTPUT_DIR/"
echo ""
echo "📂 Fichiers créés:"
ls -lh "$OUTPUT_DIR/"

echo ""
echo "🔄 Prochaine étape: Mettre à jour manifest.json"
