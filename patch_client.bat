@echo off
rem ============================================================
rem  Albion Online client -> local server build (address + no BattlEye)
rem  What exactly changes: see manifest.json and README.md (list below too)
rem  Usage:   patch_client.bat                       (from ..\game  to ..\game-local)
rem           patch_client.bat <input.dll>           (patch only, no copy)
rem           patch_client.bat <input.dll> <client folder to copy into>
rem  Never touches the input file: result goes to  patcher\out\GameAssembly.dll
rem ============================================================
setlocal
cd /d "%~dp0"
set SRC=%~1
if "%SRC%"=="" set SRC=..\game\GameAssembly.dll
set DEST=%~2
if "%DEST%"=="" set DEST=..\game-local
set PY=
where py >nul 2>nul && set PY=py -3
if not defined PY ( where python >nul 2>nul && set PY=python )
if not defined PY (
  echo Python 3 not found. Install it from python.org, or run:  python patch_albion.py --help
  pause
  exit /b 1
)
echo.
%PY% -I patch_albion.py --list
echo.
if not exist "%SRC%" (
  echo Input file not found: %SRC%
  echo Put the ORIGINAL client into the ..\game folder, or pass its full path as argument 1.
  pause
  exit /b 1
)
%PY% -I patch_albion.py "%SRC%" -o out\GameAssembly.dll --copy-to "%DEST%"
set RC=%ERRORLEVEL%
echo.
if "%RC%"=="0" (
  echo DONE. Patched file: %~dp0out\GameAssembly.dll
  echo sha256 of result and the per-site byte list are printed above; report: %~dp0out\patch_report.txt
) else (
  echo FAILED with code %RC%. The lines above name the address and the bytes that did not match.
)
pause
