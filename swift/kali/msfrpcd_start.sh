#!/bin/bash
# Start msfrpcd inside Kali container for MetasploitRunner
# Usage: docker exec <container> bash /msfrpcd_start.sh
msfrpcd -P swift -a 0.0.0.0 -p 55553 -S &
sleep 5
echo "msfrpcd started on port 55553"
