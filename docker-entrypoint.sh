#!/bin/sh
set -e

# Configuration par defaut si non existante
if [ ! -f /app/data/config.json ]; then
    echo "Creating default config..."
    cat > /app/data/config.json << 'EOF'
{
  "port": 6697,
  "certFile": "/app/certs/server.crt",
  "keyFile": "/app/certs/server.key",
  "usersFile": "/app/data/users.json",
  "tokensFile": "/app/data/tokens.json",
  "maxConnections": 100,
  "rateLimit": 10
}
EOF
fi

# Fichier users.json si non existant
if [ ! -f /app/data/users.json ]; then
    echo "Creating empty users registry..."
    echo '{}' > /app/data/users.json
fi

# Fichier tokens.json si non existant
if [ ! -f /app/data/tokens.json ]; then
    echo "Creating empty tokens registry..."
    echo '{}' > /app/data/tokens.json
fi

# Generer les certificats TLS si non existants
if [ ! -f /app/certs/server.crt ] || [ ! -f /app/certs/server.key ]; then
    echo "Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout /app/certs/server.key \
        -out /app/certs/server.crt \
        -days 365 -nodes \
        -subj '/CN=murmur/O=Murmur Chat/C=FR'
fi

echo "Starting MURMUR server..."
exec "$@"
