@echo off
echo ========================================
echo VirtualAllocTracker - Compilation
echo Ayi NEDJIMI Consultants
echo ========================================
echo.

where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Compilateur MSVC non trouve
    echo Executez depuis "Developer Command Prompt for VS"
    pause
    exit /b 1
)

echo [1/3] Compilation...
cl.exe /EHsc /O2 /W4 /std:c++17 ^
    /D UNICODE /D _UNICODE ^
    VirtualAllocTracker.cpp ^
    /link ^
    comctl32.lib psapi.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib ^
    /OUT:VirtualAllocTracker.exe

if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Echec de compilation
    pause
    exit /b 1
)

echo [2/3] Nettoyage...
del *.obj 2>nul

echo [3/3] Termine!
echo.
echo Executable: VirtualAllocTracker.exe
echo.
pause
