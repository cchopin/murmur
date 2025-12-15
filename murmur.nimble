# Package

version       = "0.1.0"
author        = "Murmur Team"
description   = "Serveur de chat securise style IRC"
license       = "MIT"
srcDir        = "src"
bin           = @["murmur_server"]


# Dependencies

requires "nim >= 2.0.0"
requires "nimcrypto >= 0.6.0"

# Enable SSL support
switch("define", "ssl")

task keygen, "Genere une paire de cles Ed25519":
  exec "nim c -r tools/keygen.nim"

task gencert, "Genere un certificat TLS auto-signe":
  exec "openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj '/CN=murmur'"
