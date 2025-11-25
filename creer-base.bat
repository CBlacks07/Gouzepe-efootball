@echo off
echo ========================================
echo   CREATION DE LA BASE DE DONNEES
echo ========================================
echo.
echo Ce script va creer la base de donnees EFOOTBALL
echo.
echo ATTENTION: Il vous demandera le mot de passe PostgreSQL
echo.
pause

psql -U postgres -c "CREATE DATABASE \"EFOOTBALL\";"

if %errorlevel% equ 0 (
    echo.
    echo ✓ Base de donnees creee avec succes!
    echo.
) else (
    echo.
    echo × Erreur lors de la creation
    echo.
    echo Verifiez que:
    echo 1. PostgreSQL est installe
    echo 2. PostgreSQL est demarre
    echo 3. Le mot de passe est correct
    echo.
)

pause
