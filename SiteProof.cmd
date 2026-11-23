@echo off
rem SiteProof launcher: double-click to start the local app (the same as: py -3.15 -B -m src.noxiworks.app).
rem Options are passed through, e.g. SiteProof.cmd --data D:\SiteProofData
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title SiteProof
set PYTHONDONTWRITEBYTECODE=1
set "SP_PY="
for %%V in (3.15 3.14 3.13 3.12) do (
  if not defined SP_PY (
    py -%%V -c "import sys" >nul 2>nul && set "SP_PY=py -%%V"
  )
)
if not defined SP_PY (
  python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>nul && set "SP_PY=python"
)
if not defined SP_PY goto nopython
echo SiteProof を起動しています…（このウィンドウを閉じると SiteProof も終了します）
%SP_PY% -B -m src.noxiworks.app %*
if errorlevel 1 (
  echo.
  echo SiteProof が終了しました（エラーコード %errorlevel%）。上のメッセージを確認してください。
  pause
)
exit /b

:nopython
echo.
echo SiteProof を起動できません：Python 3.12 以降が見つかりませんでした。
echo   1. https://www.python.org/ から Python 3.12 以降をインストールしてください
echo      （インストール時に「py launcher」を有効にしてください）。
echo   2. インストール後、もう一度この SiteProof.cmd をダブルクリックしてください。
echo.
pause
exit /b 1
