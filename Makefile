# Makefile pour MURMUR

.PHONY: all build run stop logs keygen clean docker-build docker-run docker-stop help

# Configuration
IMAGE_NAME = murmur-server
CONTAINER_NAME = murmur-server

# =============================================================================
# Developpement local
# =============================================================================

all: build

build:
	@echo "Building MURMUR server..."
	nimble build -d:release

keygen:
	@echo "Building keygen tool..."
	nim c -d:release -d:ssl tools/keygen.nim

certs:
	@echo "Generating TLS certificates..."
	@mkdir -p certs
	openssl req -x509 -newkey rsa:4096 \
		-keyout certs/server.key \
		-out certs/server.crt \
		-days 365 -nodes \
		-subj '/CN=murmur/O=Murmur Chat/C=FR'

run: certs
	@echo "Starting MURMUR server..."
	./murmur_server

clean:
	@echo "Cleaning build artifacts..."
	rm -f murmur_server
	rm -f tools/keygen
	rm -rf nimcache/

# =============================================================================
# Docker
# =============================================================================

docker-build:
	@echo "Building Docker image..."
	docker build -t $(IMAGE_NAME) .

docker-run:
	@echo "Starting MURMUR in Docker..."
	docker-compose up -d
	@echo ""
	@echo "MURMUR is running on port 6697"
	@echo "Logs: make docker-logs"
	@echo "Stop: make docker-stop"

docker-stop:
	@echo "Stopping MURMUR..."
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-shell:
	docker exec -it $(CONTAINER_NAME) /bin/sh

# =============================================================================
# Gestion des utilisateurs
# =============================================================================

# Usage: make add-user USER=alice
add-user:
ifndef USER
	@echo "Usage: make add-user USER=<username>"
	@exit 1
endif
	@echo "Generating keys for user: $(USER)"
	@if [ -f tools/keygen ]; then \
		./tools/keygen $(USER) -r; \
	else \
		docker exec $(CONTAINER_NAME) ./tools/keygen $(USER) -r -f /app/data/users.json; \
	fi

# Generate invitation token
invite:
	@echo "Generating invitation token..."
	@if [ -f tools/keygen ]; then \
		./tools/keygen -i; \
	else \
		docker exec $(CONTAINER_NAME) ./tools/keygen -i -t /app/data/tokens.json; \
	fi

# =============================================================================
# Help
# =============================================================================

help:
	@echo "MURMUR - Serveur de chat securise"
	@echo ""
	@echo "Commandes disponibles:"
	@echo "  make build        - Compile le serveur"
	@echo "  make keygen       - Compile l'outil de generation de cles"
	@echo "  make certs        - Genere les certificats TLS"
	@echo "  make run          - Lance le serveur localement"
	@echo "  make clean        - Nettoie les fichiers de build"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build - Build l'image Docker"
	@echo "  make docker-run   - Lance le serveur dans Docker"
	@echo "  make docker-stop  - Arrete le serveur Docker"
	@echo "  make docker-logs  - Affiche les logs"
	@echo "  make docker-shell - Ouvre un shell dans le container"
	@echo ""
	@echo "Utilisateurs:"
	@echo "  make add-user USER=alice - Ajoute un utilisateur (mode admin)"
	@echo "  make invite              - Genere un token d'invitation"
