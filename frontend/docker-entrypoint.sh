#!/bin/sh
set -e

# Replace placeholder in config.js with actual environment variable
if [ -n "$VITE_API_URL" ]; then
  echo "Configuring API URL: $VITE_API_URL"
  sed -i "s|__API_URL__|$VITE_API_URL|g" /app/dist/config.js
else
  echo "Warning: VITE_API_URL not set, using default /api"
  sed -i "s|__API_URL__|/api|g" /app/dist/config.js
fi

# Execute the main command
exec "$@"
