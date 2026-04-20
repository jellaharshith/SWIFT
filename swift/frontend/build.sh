#!/bin/bash
set -e
sed -i "s|%%SWIFT_API_URL%%|${SWIFT_API_URL}|g" index.html
echo "SWIFT_API_URL injected: ${SWIFT_API_URL}"
