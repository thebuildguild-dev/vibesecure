#!/bin/sh
set -e

cat > /usr/share/nginx/html/config.js << EOF
window.__APP_CONFIG__ = {
  apiBase: "${VITE_API_BASE:-/api}",
  firebase: {
    apiKey: "${VITE_FIREBASE_API_KEY}",
    authDomain: "${VITE_FIREBASE_AUTH_DOMAIN}",
    projectId: "${VITE_FIREBASE_PROJECT_ID}",
    storageBucket: "${VITE_FIREBASE_STORAGE_BUCKET}",
    messagingSenderId: "${VITE_FIREBASE_MESSAGING_SENDER_ID}",
    appId: "${VITE_FIREBASE_APP_ID}"
  }
};
EOF

echo "Runtime configuration generated"

exec "$@"
