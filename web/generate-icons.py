#!/usr/bin/env python3
"""
Script pour générer les icônes PWA à partir du logo
Nécessite: pip install Pillow
"""

import os
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("❌ Pillow n'est pas installé.")
    print("\n📋 Installation:")
    print("   pip install Pillow")
    print("   ou: pip3 install Pillow")
    sys.exit(1)

# Configuration
LOGO = "web/assets/fond.png"
OUTPUT_DIR = "web/assets/icons"
BRAND_COLOR = (22, 163, 74)  # #16a34a

# Tailles d'icônes à générer
SIZES = [
    (48, 48),
    (72, 72),
    (96, 96),
    (144, 144),
    (192, 192),
    (512, 512),
]

def create_directory():
    """Crée le dossier de sortie s'il n'existe pas"""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

def generate_icon(logo, size, output_path, background=None, padding=0):
    """Génère une icône à partir du logo"""
    try:
        # Ouvrir l'image
        img = Image.open(logo)

        # Convertir en RGBA si nécessaire
        if img.mode != 'RGBA':
            img = img.convert('RGBA')

        # Calculer la taille avec padding
        target_size = size - (padding * 2)

        # Redimensionner en gardant le ratio
        img.thumbnail((target_size, target_size), Image.Resampling.LANCZOS)

        # Créer une nouvelle image avec fond
        if background:
            new_img = Image.new('RGBA', (size, size), background)
        else:
            new_img = Image.new('RGBA', (size, size), (0, 0, 0, 0))

        # Centrer l'image redimensionnée
        offset = ((size - img.width) // 2, (size - img.height) // 2)
        new_img.paste(img, offset, img)

        # Sauvegarder
        new_img.save(output_path, 'PNG', optimize=True)

        print(f"✅ Créé: {output_path}")
        return True
    except Exception as e:
        print(f"❌ Erreur pour {output_path}: {e}")
        return False

def main():
    print("🎨 Génération des icônes PWA...\n")

    # Vérifier que le logo existe
    if not os.path.exists(LOGO):
        print(f"❌ Fichier logo introuvable: {LOGO}")
        sys.exit(1)

    # Créer le dossier de sortie
    create_directory()

    success_count = 0

    # Générer les icônes standard
    for width, height in SIZES:
        output = f"{OUTPUT_DIR}/icon-{width}x{height}.png"
        if generate_icon(LOGO, width, output):
            success_count += 1

    # Générer l'icône Apple Touch
    output = f"{OUTPUT_DIR}/apple-touch-icon.png"
    if generate_icon(LOGO, 180, output):
        success_count += 1

    # Générer l'icône maskable (avec fond de couleur et padding)
    output = f"{OUTPUT_DIR}/icon-maskable-512x512.png"
    if generate_icon(LOGO, 512, output, background=BRAND_COLOR + (255,), padding=51):
        success_count += 1

    # Générer le favicon
    try:
        img = Image.open(LOGO)
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        img.thumbnail((32, 32), Image.Resampling.LANCZOS)
        favicon_path = f"{OUTPUT_DIR}/favicon.ico"
        img.save(favicon_path, format='ICO', sizes=[(32, 32)])
        print(f"✅ Créé: {favicon_path}")
        success_count += 1
    except Exception as e:
        print(f"❌ Erreur favicon: {e}")

    print(f"\n🎉 {success_count} icônes générées avec succès!")
    print(f"📂 Dossier: {OUTPUT_DIR}/")

    # Lister les fichiers créés
    print("\n📋 Fichiers créés:")
    for file in sorted(Path(OUTPUT_DIR).glob("*")):
        size = file.stat().st_size / 1024
        print(f"   {file.name} ({size:.1f} KB)")

    print("\n🔄 Prochaine étape: Mettre à jour manifest.json")

if __name__ == "__main__":
    main()
