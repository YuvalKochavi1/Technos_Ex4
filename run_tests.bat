@echo off
echo Starting Docker containers...
docker-compose up -d

echo.
echo Starting web server on attacker...
docker exec -d spoof_attacker python server/app.py

echo.
echo Starting spoofing script in a new window...
start "Attacker Script" docker exec -it spoof_attacker python ex4_skeleton.py

echo.
echo Waiting 5 seconds for ARP spoofing to take effect...
timeout /t 5 /nobreak >nul

echo.
echo Testing from Victim...
echo.
echo [1] Resolving IPs from victim's perspective:
docker exec spoof_victim bash -c "echo -n '    mail.doofle.com IP: ' && dig mail.doofle.com +short | tail -n1"
docker exec spoof_victim bash -c "echo -n '    google.com IP: ' && dig google.com +short | tail -n1"
echo.

echo [2] Verifying spoofed HTML content (checking for 'save_password')...
docker exec spoof_victim bash -c "if curl -s http://mail.doofle.com | grep -q 'save_password'; then echo '    [+] SUCCESS: Spoofed page intercepted!'; else echo '    [-] FAILED: Did not find save_password'; fi"
echo.

echo [3] Testing real internet connection (google.com)...
docker exec spoof_victim bash -c "if curl -L -s http://google.com | grep -q 'save_password'; then echo '    [-] FAILED: google.com was spoofed!'; else echo '    [+] SUCCESS: Reached google.com and it is NOT spoofed!'; fi"
echo.
pause
