# Dockerfile pour MURMUR - Serveur de chat securise
# Multi-stage build pour une image legere

# ============================================================================
# Stage 1: Build
# ============================================================================
FROM nimlang/nim:2.0.0-alpine AS builder

# Installer les dependances de build
RUN apk add --no-cache \
    openssl-dev \
    openssl-libs-static \
    musl-dev \
    git

WORKDIR /build

# Copier les fichiers du projet
COPY murmur.nimble nim.cfg ./
COPY src/ ./src/
COPY tools/ ./tools/

# Installer les dependances Nim
RUN nimble install -y --depsOnly

# Compiler le serveur (static linking pour portabilite)
RUN nimble build -d:release --opt:size -y && \
    strip murmur_server

# Compiler keygen
RUN nim c -d:release -d:ssl --opt:size tools/keygen.nim && \
    strip tools/keygen

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM alpine:3.19

# Installer les dependances runtime
RUN apk add --no-cache \
    openssl \
    libgcc \
    ca-certificates \
    netcat-openbsd

# Creer un utilisateur non-root
RUN addgroup -S murmur && adduser -S murmur -G murmur

WORKDIR /app

# Copier les binaires
COPY --from=builder /build/murmur_server ./
COPY --from=builder /build/tools/keygen ./tools/

# Copier la configuration par defaut
COPY config.json ./config.json.default

# Creer les repertoires necessaires
RUN mkdir -p /app/certs /app/data && \
    chown -R murmur:murmur /app

# Script d'entrypoint (doit etre lisible par tous)
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod 755 /docker-entrypoint.sh

# Exposer le port TLS
EXPOSE 6697

# Volume pour la persistance
VOLUME ["/app/certs", "/app/data"]

# Note: On reste root pour l'entrypoint qui doit generer les certificats
# Le serveur lui-meme ne necessite pas de privileges root

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["./murmur_server", "/app/data/config.json"]
