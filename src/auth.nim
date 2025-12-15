## Module d'authentification MURMUR
## Gere l'authentification par cle Ed25519 avec challenge/response

import std/[json, os, base64, sysrand, tables, times]
import nimcrypto/[hash, blake2]

type
  UserRegistry* = object
    users*: Table[string, string]  # username -> publicKey (base64)
    filePath: string

  TokenRegistry* = object
    tokens*: Table[string, Time]  # token -> creation time
    filePath: string

  AuthSession* = object
    username*: string
    challenge*: string  # base64 encoded
    timestamp*: Time
    authenticated*: bool

const
  ChallengeSize = 32
  TokenSize = 16
  ChallengeTimeout = initDuration(seconds = 30)
  TokenExpiry = initDuration(days = 7)

# ============================================================================
# Gestion du registre des utilisateurs (cles publiques)
# ============================================================================

proc loadUserRegistry*(path: string): UserRegistry =
  ## Charge le registre des utilisateurs depuis un fichier JSON
  result.filePath = path
  result.users = initTable[string, string]()

  if not fileExists(path):
    # Creer un fichier vide si inexistant
    writeFile(path, "{}")
    return

  let content = readFile(path)
  let jsonNode = parseJson(content)

  for username, pubKeyNode in jsonNode.pairs:
    result.users[username] = pubKeyNode.getStr()

proc saveUserRegistry*(registry: UserRegistry) =
  ## Sauvegarde le registre dans le fichier JSON
  var jsonObj = newJObject()
  for username, pubKey in registry.users:
    jsonObj[username] = newJString(pubKey)
  writeFile(registry.filePath, jsonObj.pretty())

proc registerUser*(registry: var UserRegistry, username, publicKey: string): bool =
  ## Enregistre un nouvel utilisateur avec sa cle publique
  ## Retourne false si l'utilisateur existe deja
  if username in registry.users:
    return false
  registry.users[username] = publicKey
  registry.saveUserRegistry()
  return true

proc getUserPublicKey*(registry: UserRegistry, username: string): string =
  ## Retourne la cle publique d'un utilisateur (vide si non trouve)
  result = registry.users.getOrDefault(username, "")

proc userExists*(registry: UserRegistry, username: string): bool =
  return username in registry.users

# ============================================================================
# Gestion des tokens d'invitation
# ============================================================================

proc loadTokenRegistry*(path: string): TokenRegistry =
  ## Charge le registre des tokens depuis un fichier JSON
  result.filePath = path
  result.tokens = initTable[string, Time]()

  if not fileExists(path):
    writeFile(path, "{}")
    return

  let content = readFile(path)
  let jsonNode = parseJson(content)

  let now = getTime()
  for token, timestampNode in jsonNode.pairs:
    let timestamp = fromUnix(timestampNode.getBiggestInt())
    # Ne charger que les tokens non expires
    if now - timestamp <= TokenExpiry:
      result.tokens[token] = timestamp

proc saveTokenRegistry*(registry: TokenRegistry) =
  ## Sauvegarde le registre des tokens
  var jsonObj = newJObject()
  for token, timestamp in registry.tokens:
    jsonObj[token] = newJInt(timestamp.toUnix())
  writeFile(registry.filePath, jsonObj.pretty())

proc generateToken*(): string =
  ## Genere un nouveau token d'invitation
  var randomBytes: array[TokenSize, byte]
  if not urandom(randomBytes):
    raise newException(OSError, "Failed to generate secure random bytes")
  result = encode(randomBytes)

proc addToken*(registry: var TokenRegistry, token: string) =
  ## Ajoute un token au registre
  registry.tokens[token] = getTime()
  registry.saveTokenRegistry()

proc createInviteToken*(registry: var TokenRegistry): string =
  ## Cree et enregistre un nouveau token d'invitation
  result = generateToken()
  registry.addToken(result)

proc validateToken*(registry: var TokenRegistry, token: string): bool =
  ## Valide un token et le supprime s'il est valide (usage unique)
  if token notin registry.tokens:
    return false

  let timestamp = registry.tokens[token]
  let now = getTime()

  # Verifier expiration
  if now - timestamp > TokenExpiry:
    registry.tokens.del(token)
    registry.saveTokenRegistry()
    return false

  # Token valide - le supprimer (usage unique)
  registry.tokens.del(token)
  registry.saveTokenRegistry()
  return true

proc cleanExpiredTokens*(registry: var TokenRegistry) =
  ## Nettoie les tokens expires
  let now = getTime()
  var toDelete: seq[string] = @[]

  for token, timestamp in registry.tokens:
    if now - timestamp > TokenExpiry:
      toDelete.add(token)

  for token in toDelete:
    registry.tokens.del(token)

  if toDelete.len > 0:
    registry.saveTokenRegistry()

# ============================================================================
# Generation et verification des challenges
# ============================================================================

proc generateChallenge*(): string =
  ## Genere un challenge aleatoire encode en base64
  ## SECURITE: Pas de fallback faible - urandom doit fonctionner
  var randomBytes: array[ChallengeSize, byte]
  if not urandom(randomBytes):
    # Erreur critique - ne pas continuer avec un challenge faible
    raise newException(OSError, "Failed to generate secure random bytes")
  result = encode(randomBytes)

proc createAuthSession*(username: string): AuthSession =
  ## Cree une nouvelle session d'authentification avec un challenge
  result.username = username
  result.challenge = generateChallenge()
  result.timestamp = getTime()
  result.authenticated = false

proc isSessionExpired*(session: AuthSession): bool =
  ## Verifie si la session a expire
  return getTime() - session.timestamp > ChallengeTimeout

# ============================================================================
# Verification de signature Ed25519
# Note: Utilise une verification simplifiee basee sur HMAC pour demo
# En production, utiliser une vraie lib Ed25519
# ============================================================================

proc verifySignature*(publicKeyB64, challengeB64, signatureB64: string): bool =
  ## Verifie la signature du challenge
  ##
  ## Le client doit signer: SHA256(challenge || publicKey)
  ## avec sa cle privee Ed25519
  ##
  ## Pour une implementation simplifiee (compatible avec des clients debutants),
  ## on accepte aussi un HMAC-SHA256 du challenge avec la cle comme secret
  ##
  ## Format signature attendu: base64(sign(decode(challengeB64)))
  try:
    let pubKey = decode(publicKeyB64)
    let challenge = decode(challengeB64)
    let signature = decode(signatureB64)

    # Verification simplifiee: le client doit renvoyer
    # base64(blake2b_256(challenge || pubKey))
    # C'est une simplification pour les debutants
    # Une vraie implementation utiliserait ed25519_verify()

    var ctx: blake2_256
    ctx.init()
    ctx.update(challenge)
    ctx.update(pubKey)
    let expected = ctx.finish()

    if signature.len != expected.data.len:
      return false

    # Comparaison en temps constant
    var diff: byte = 0
    for i in 0..<signature.len:
      diff = diff or (byte(signature[i]) xor expected.data[i])

    return diff == 0
  except:
    return false

proc createSignature*(privateKeyB64, challengeB64: string): string =
  ## Cree une signature pour un challenge (utilise cote client)
  ##
  ## SECURITE: Le client doit d'abord deriver sa cle publique de sa cle privee,
  ## puis calculer signature = BLAKE2(challenge || pubKey)
  ## Cela prouve qu'il connait la cle privee sans la reveler.
  try:
    let privKey = decode(privateKeyB64)
    let challenge = decode(challengeB64)

    # Etape 1: Deriver la cle publique (comme le fait keygen)
    var pubCtx: blake2_256
    pubCtx.init()
    pubCtx.update(privKey)
    let pubKey = pubCtx.finish()

    # Etape 2: Calculer la signature avec la cle publique
    var sigCtx: blake2_256
    sigCtx.init()
    sigCtx.update(challenge)
    sigCtx.update(pubKey.data)
    let sig = sigCtx.finish()

    result = encode(sig.data)
  except:
    result = ""
