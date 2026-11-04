@echo off
title Bank Fraud Detector - C Web App
cd /d "%~dp0"
where gcc >nul 2>nul
if errorlevel 1 (
  echo GCC was not found. Install MSYS2 MinGW-w64 GCC and add its bin folder to PATH.
  echo Example: C:\msys64\mingw64\bin
  pause
  exit /b 1
)
echo Compiling Bank Fraud Detector...
gcc main.c -o bank_fraud_detector.exe -lws2_32 -O2 -Wall
if errorlevel 1 (
  echo Compilation failed. Check the error messages above.
  pause
  exit /b 1
)
echo.
echo Starting server. Keep this window open.
bank_fraud_detector.exe
pause
