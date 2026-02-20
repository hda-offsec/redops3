#!/bin/bash
# Script de nettoyage d'urgence pour libérer de l'espace disque

echo "============================================="
echo "   NETTOYAGE D'URGENCE - ESPACE DISQUE       "
echo "============================================="

# 1. Nettoyage du cache APT (Nécessite sudo)
echo "[*] Nettoyage du cache des paquets apt (sudo requis)..."
sudo apt-get clean

# 2. Nettoyage des caches utilisateur (Sans danger)
echo "[*] Nettoyage du cache des builds Go (~1.9 Go)..."
rm -rf ~/.cache/go-build

echo "[*] Nettoyage du cache pip (~250 Mo)..."
rm -rf ~/.cache/pip

echo "[*] Nettoyage du cache Trivy (~900 Mo)..."
rm -rf ~/.cache/trivy

# echo "[*] Nettoyage du cache Playwright (~1 Go)..."
# rm -rf ~/.cache/ms-playwright

# 3. Vérification finale
echo "============================================="
echo "   ESPACE DISPONIBLE APRÈS NETTOYAGE         "
echo "============================================="
df -h /

echo ""
echo "Vous pouvez maintenant relancer ./start_redops.sh si l'espace est suffisant."
