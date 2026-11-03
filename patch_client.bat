@echo off
setlocal EnableExtensions EnableDelayedExpansion
pushd "%~dp0.."

set "PYTHON_CMD="
where python >nul 2>nul && set "PYTHON_CMD=python"
if not defined PYTHON_CMD where py >nul 2>nul && set "PYTHON_CMD=py"
if not defined PYTHON_CMD (
  echo ERROR: Python 3 is not installed or not in PATH.
  popd
  exit /b 2
)

set "INPUT=game\GameAssembly.dll"
set "METADATA=game\Albion-Online_Data\il2cpp_data\Metadata\global-metadata.dat"
set "PATCHER=%~dp0patch_albion.py"
set "OUTPUT=game\GameAssembly.dll.new"
set "LOG=work\patch_client.log"
set "OUTPUT_SHA="

if not exist "%INPUT%" (
  echo ERROR: client DLL not found: %INPUT%
  popd
  exit /b 2
)
if not exist "%METADATA%" (
  echo ERROR: metadata not found: %METADATA%
  popd
  exit /b 2
)
if not exist "%PATCHER%" (
  echo ERROR: patcher not found: %PATCHER%
  popd
  exit /b 2
)

if not exist "work" mkdir "work"
if exist "%OUTPUT%" del /F /Q "%OUTPUT%"

echo Checking patch targets with a dry run...
"%PYTHON_CMD%" "%PATCHER%" --dry-run --dll "%INPUT%" --metadata "%METADATA%" --output "work\GameAssembly.dll.dryrun" > "%LOG%" 2>&1
if errorlevel 1 goto fail

echo Applying patches to a .new file...
"%PYTHON_CMD%" "%PATCHER%" --dll "%INPUT%" --metadata "%METADATA%" --output "%OUTPUT%" > "%LOG%" 2>&1
if errorlevel 1 goto fail
if not exist "%OUTPUT%" goto fail

"%PYTHON_CMD%" -c "import os,sys; sys.exit(0 if os.path.getsize(sys.argv[1])==os.path.getsize(sys.argv[2]) else 1)" "%INPUT%" "%OUTPUT%" >nul 2>nul
if errorlevel 1 (
  echo ERROR: patched output size differs from the original DLL.
  goto fail
)

for /f "skip=1 tokens=1 delims=" %%H in ('certutil -hashfile "%OUTPUT%" SHA256') do if not defined OUTPUT_SHA set "OUTPUT_SHA=%%H"

set "TS="
for /f "usebackq delims=" %%T in (`powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"`) do set "TS=%%T"
if not defined TS set "TS=manual"
set "BACKUP=%INPUT%.bak-%TS%"

echo Creating backup: %BACKUP%
copy /Y "%INPUT%" "%BACKUP%" >nul
if errorlevel 1 goto fail

move /Y "%OUTPUT%" "%INPUT%" >nul
if errorlevel 1 goto fail

findstr /C:"Output sha256" "%LOG%" 2>nul
echo STATUS: patched
echo Backup: %BACKUP%
echo GameAssembly.dll SHA256: %OUTPUT_SHA%
echo Start the game directly: game\Albion-Online.exe
popd
exit /b 0

:fail
findstr /C:"ERROR:" "%LOG%" 2>nul
if not exist "%LOG%" (
  echo ERROR: patcher produced no log file: %LOG%
) else (
  echo See log: %LOG%
  findstr /C:"STATUS:" "%LOG%" 2>nul
  findstr /C:"Dry run:" "%LOG%" 2>nul
  findstr /C:"Planned sha256:" "%LOG%" 2>nul
  findstr /C:"Wrote:" "%LOG%" 2>nul
)
popd
exit /b 1
