@echo off
cd /d "%~dp0"
where java >nul 2>nul || (echo Java 17+ was not found on PATH.& exit /b 1)
where mvn >nul 2>nul || (echo Maven 3.9+ was not found on PATH.& exit /b 1)
if not exist target\netsentry.jar mvn clean package
if errorlevel 1 exit /b 1
java -jar target\netsentry.jar web
