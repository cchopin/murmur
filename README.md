# MURMUR

Secure IRC-style chat server written in Nim. Features TLS encryption and asymmetric key authentication.

## Features

- TLS 1.2+ encryption (mandatory)
- Challenge-response authentication (no passwords transmitted)
- Public rooms and private messaging
- Ephemeral messages (no server-side persistence)
- Rate limiting and brute-force protection
- Docker deployment ready

## Quick Start

### Docker Deployment

```bash
git clone <repository>
cd murmur
make docker-run
```

The server starts on port **6697** (TLS).

### Add Users

```bash
make add-user USER=alice
```

This generates a key pair and registers the public key. The private key is displayed once and must be saved securely.

### View Logs

```bash
make docker-logs
```

## Protocol Documentation

See [RFC_MURMUR.md](RFC_MURMUR.md) for the complete protocol specification. This document contains all information required to implement a client.

## Project Structure

```
murmur/
├── src/
│   ├── murmur_server.nim    # Server entry point
│   ├── protocol.nim         # Protocol parsing
│   ├── auth.nim             # Authentication
│   ├── rooms.nim            # Room management
│   └── users.nim            # Connection management
├── tools/
│   └── keygen.nim           # Key generation utility
├── Dockerfile
├── docker-compose.yml
├── RFC_MURMUR.md            # Protocol specification
└── Makefile
```

## Available Commands

```bash
make help              # Show help
make docker-run        # Start server
make docker-stop       # Stop server
make docker-logs       # View logs
make add-user USER=x   # Add user (admin mode)
make invite            # Generate invitation token
```

## User Registration

MURMUR uses invitation tokens for self-registration. Users generate their own keys locally.

### For Administrators: Invite a User

```bash
# Generate an invitation token (valid 7 days)
docker exec murmur-server ./tools/keygen -i -t /app/data/tokens.json
```

Send the token to the new user.

### For New Users: Register

**Step 1: Generate your keys locally**

```python
# save as keygen.py and run: python3 keygen.py
import hashlib, base64, os
private_key = os.urandom(32)
public_key = hashlib.blake2b(private_key, digest_size=32).digest()
print("PRIVATE KEY (keep secret!):")
print(base64.b64encode(private_key).decode())
print("\nPUBLIC KEY:")
print(base64.b64encode(public_key).decode())
```

Save your private key securely.

**Step 2: Connect to the server**

```bash
openssl s_client -connect <server>:6697
```

**Step 3: Register with your token**

```
REGISTER <username> <public_key> <token>
```

Response: `OK REGISTER <username>`

**Step 4: Authenticate**

```
HELLO <username>
```

Server sends: `CHALLENGE <nonce>`

Compute signature and send:
```
AUTH <signature>
```

Response: `WELCOME <username>`

See [RFC_MURMUR.md](RFC_MURMUR.md) for signature computation details.

## Client Connection

### Direct Connection (LAN)

```bash
openssl s_client -connect <server-ip>:6697
```

### Via Cloudflare Tunnel (Public Access)

If the server is behind a Cloudflare Tunnel:

```bash
# Install cloudflared
# Linux: curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared && chmod +x cloudflared
# macOS: brew install cloudflared
# Windows: winget install Cloudflare.cloudflared

# Start local tunnel
cloudflared access tcp --hostname <tunnel-hostname> --url localhost:6697

# Connect via localhost
openssl s_client -connect localhost:6697
```

## Security

| Feature | Description |
|---------|-------------|
| Transport | TLS 1.2+ mandatory |
| Authentication | BLAKE2b-256 challenge-response |
| Rate Limiting | Configurable (default: 10 msg/sec) |
| Brute Force Protection | 5 failures = 5 min lockout |
| Data Persistence | None (ephemeral) |

## Configuration

Server configuration is stored in `config.json`:

```json
{
  "port": 6697,
  "certFile": "certs/server.crt",
  "keyFile": "certs/server.key",
  "usersFile": "users.json",
  "maxConnections": 100,
  "rateLimit": 10
}
```

## License

MIT
