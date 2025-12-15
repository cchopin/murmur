## Outil de generation de cles pour MURMUR
## Genere une paire de cles et peut enregistrer l'utilisateur sur le serveur
## Peut aussi generer des tokens d'invitation

import std/[os, json, base64, sysrand, parseopt, times]
import nimcrypto/[hash, blake2]

const
  KeySize = 32
  TokenSize = 16

proc generateKeyPair(): (string, string) =
  ## Genere une paire de cles (privee, publique) encodees en base64
  ## Utilise des bytes aleatoires comme "cle privee"
  ## La "cle publique" est derivee de la cle privee via blake2

  var privateBytes: array[KeySize, byte]
  if not urandom(privateBytes):
    echo "ERREUR: Impossible de generer des bytes aleatoires"
    quit(1)

  # Deriver la cle publique de la cle privee
  var ctx: blake2_256
  ctx.init()
  ctx.update(privateBytes)
  let publicBytes = ctx.finish()

  let privateKey = encode(privateBytes)
  let publicKey = encode(publicBytes.data)

  return (privateKey, publicKey)

proc registerUser(usersFile, username, publicKey: string): bool =
  ## Enregistre un utilisateur dans le fichier users.json
  var users: JsonNode

  if fileExists(usersFile):
    let content = readFile(usersFile)
    users = parseJson(content)
  else:
    users = newJObject()

  if users.hasKey(username):
    echo "ERREUR: L'utilisateur '", username, "' existe deja"
    return false

  users[username] = newJString(publicKey)
  writeFile(usersFile, users.pretty())
  return true

proc generateInviteToken(): string =
  ## Genere un token d'invitation aleatoire
  var tokenBytes: array[TokenSize, byte]
  if not urandom(tokenBytes):
    echo "ERREUR: Impossible de generer des bytes aleatoires"
    quit(1)
  return encode(tokenBytes)

proc addInviteToken(tokensFile, token: string): bool =
  ## Ajoute un token au registre des tokens
  var tokens: JsonNode

  if fileExists(tokensFile):
    let content = readFile(tokensFile)
    tokens = parseJson(content)
  else:
    tokens = newJObject()

  tokens[token] = newJInt(getTime().toUnix())
  writeFile(tokensFile, tokens.pretty())
  return true

proc printUsage() =
  echo """
MURMUR Key Generator & Invite Tool

Usage:
  keygen <username>              Genere des cles et les affiche
  keygen <username> --register   Genere des cles et enregistre l'utilisateur
  keygen --invite                Genere un token d'invitation
  keygen --help                  Affiche cette aide

Options:
  --register, -r    Enregistre automatiquement la cle publique dans users.json
  --file, -f        Chemin vers users.json (defaut: users.json)
  --output, -o      Sauvegarde les cles dans des fichiers
  --invite, -i      Genere un token d'invitation (pas de username requis)
  --tokens, -t      Chemin vers tokens.json (defaut: tokens.json)

Exemples:
  keygen alice                   # Genere les cles pour alice
  keygen alice -r                # Genere et enregistre alice
  keygen bob -r -f ../users.json # Enregistre bob dans un fichier specifique
  keygen charlie -o              # Sauvegarde dans charlie.key et charlie.pub
  keygen -i                      # Genere un token d'invitation
  keygen -i -t /app/data/tokens.json  # Token dans un fichier specifique

Workflow d'inscription:
  1. L'admin genere un token:  keygen -i
  2. L'admin envoie le token au nouvel utilisateur
  3. L'utilisateur genere ses cles:  keygen monnom
  4. L'utilisateur s'inscrit via le client: REGISTER monnom <pubkey> <token>
"""

proc main() =
  var
    username = ""
    register = false
    usersFile = "users.json"
    tokensFile = "tokens.json"
    outputFiles = false
    generateInvite = false
    expectingFile = false
    expectingTokensFile = false

  # Parser les arguments
  var p = initOptParser()
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "help", "h":
        printUsage()
        quit(0)
      of "register", "r":
        register = true
      of "file", "f":
        if p.val.len > 0:
          usersFile = p.val
        else:
          expectingFile = true
      of "output", "o":
        outputFiles = true
      of "invite", "i":
        generateInvite = true
      of "tokens", "t":
        if p.val.len > 0:
          tokensFile = p.val
        else:
          expectingTokensFile = true
      else:
        echo "Option inconnue: ", p.key
        quit(1)
    of cmdArgument:
      if expectingFile:
        usersFile = p.key
        expectingFile = false
      elif expectingTokensFile:
        tokensFile = p.key
        expectingTokensFile = false
      elif username == "":
        username = p.key
      else:
        echo "Trop d'arguments: ", p.key
        quit(1)

  # Mode generation de token d'invitation
  if generateInvite:
    echo "=== MURMUR Invite Token Generator ==="
    echo ""
    let token = generateInviteToken()
    discard addInviteToken(tokensFile, token)
    echo "Token d'invitation (valide 7 jours):"
    echo token
    echo ""
    echo "Token enregistre dans: ", tokensFile
    echo ""
    echo "Envoie ce token a l'utilisateur. Il pourra s'inscrire avec:"
    echo "  REGISTER <username> <public_key> ", token
    quit(0)

  if username == "":
    printUsage()
    quit(1)

  # Valider le username
  if username.len > 32:
    echo "ERREUR: Le username ne doit pas depasser 32 caracteres"
    quit(1)

  for c in username:
    if c notin {'a'..'z', 'A'..'Z', '0'..'9', '_'}:
      echo "ERREUR: Le username ne peut contenir que des lettres, chiffres et _"
      quit(1)

  echo "=== MURMUR Key Generator ==="
  echo ""

  # Generer les cles
  let (privateKey, publicKey) = generateKeyPair()

  echo "Username:    ", username
  echo ""
  echo "Cle privee (A GARDER SECRETE!):"
  echo privateKey
  echo ""
  echo "Cle publique:"
  echo publicKey
  echo ""

  # Sauvegarder dans des fichiers si demande
  if outputFiles:
    let keyFile = username & ".key"
    let pubFile = username & ".pub"

    writeFile(keyFile, privateKey)
    writeFile(pubFile, publicKey)

    echo "Cles sauvegardees dans:"
    echo "  - ", keyFile, " (CLE PRIVEE - A GARDER SECRETE!)"
    echo "  - ", pubFile, " (cle publique)"
    echo ""

  # Enregistrer si demande
  if register:
    if registerUser(usersFile, username, publicKey):
      echo "Utilisateur enregistre dans: ", usersFile
    else:
      quit(1)
  else:
    echo "Pour enregistrer cet utilisateur sur le serveur, ajoute cette ligne"
    echo "dans users.json (ou utilise --register):"
    echo ""
    echo "  \"", username, "\": \"", publicKey, "\""
    echo ""

  echo "=== Instructions pour le client ==="
  echo ""
  echo "1. Le client doit stocker la CLE PRIVEE de maniere securisee"
  echo "2. Pour s'authentifier:"
  echo "   a. Envoyer: HELLO ", username
  echo "   b. Recevoir: CHALLENGE <nonce_base64>"
  echo "   c. Calculer: signature = base64(blake2b_256(decode(nonce) || decode(privateKey)))"
  echo "   d. Envoyer: AUTH <signature>"
  echo "   e. Recevoir: WELCOME ", username, " (si OK)"
  echo ""

when isMainModule:
  main()
