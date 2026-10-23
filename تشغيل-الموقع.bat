@echo off
chcp 65001 >nul
title منظومة إدارة المدارس - التشغيل
cd /d "%~dp0"
echo.
echo   جاري تشغيل الخادم والواجهة...
echo   لا تغلق نافذة التشغيل أثناء الاستخدام.
echo.
start "OC School - Dev" cmd /k "npm run dev"
timeout /t 9 /nobreak >nul
start "" "http://localhost:5173"
exit