@echo off
setlocal

set "ENV_FILE=.env"
set "JAR_FILE=target/auth-micro-0.0.1-SNAPSHOT.jar"

if not exist "%ENV_FILE%" (
    echo Environment file not found: "%ENV_FILE%"
    endlocal
    exit /b 1
)

if not exist "%JAR_FILE%" (
    echo JAR file not found: "%JAR_FILE%"
    endlocal
    exit /b 1
)
echo MEEEEEEP

echo Starting authentication host with the following environment variables:
for /f "tokens=1* delims==" %%a in ('type "%ENV_FILE%"') do (
    set "%%a=%%b"
    echo "%%a=%%b"
)

java -jar "%JAR_FILE%"

pause
endlocal