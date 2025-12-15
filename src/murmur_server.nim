## Serveur MURMUR - Chat securise style IRC
## Point d'entree principal du serveur

import std/[asyncdispatch, asyncnet, net, json, os, strutils, logging, tables]
import protocol, auth, rooms, users

# ============================================================================
# Configuration
# ============================================================================

type
  ServerConfig = object
    port: int
    certFile: string
    keyFile: string
    usersFile: string
    tokensFile: string
    maxConnections: int
    rateLimit: int  # messages par seconde

var
  config: ServerConfig
  userRegistry: UserRegistry
  tokenRegistry: TokenRegistry
  clientManager: ClientManager
  roomManager: RoomManager
  logger: ConsoleLogger

proc loadConfig(path: string): ServerConfig =
  if not fileExists(path):
    # Configuration par defaut
    result.port = 6697
    result.certFile = "certs/server.crt"
    result.keyFile = "certs/server.key"
    result.usersFile = "users.json"
    result.tokensFile = "tokens.json"
    result.maxConnections = 100
    result.rateLimit = 10
    return

  let content = readFile(path)
  let jsonNode = parseJson(content)

  result.port = jsonNode.getOrDefault("port").getInt(6697)
  result.certFile = jsonNode.getOrDefault("certFile").getStr("certs/server.crt")
  result.keyFile = jsonNode.getOrDefault("keyFile").getStr("certs/server.key")
  result.usersFile = jsonNode.getOrDefault("usersFile").getStr("users.json")
  result.tokensFile = jsonNode.getOrDefault("tokensFile").getStr("tokens.json")
  result.maxConnections = jsonNode.getOrDefault("maxConnections").getInt(100)
  result.rateLimit = jsonNode.getOrDefault("rateLimit").getInt(10)

# ============================================================================
# Gestion des messages
# ============================================================================

proc sendToClient(client: Client, message: string) {.async.} =
  ## Envoie un message a un client specifique
  try:
    await client.socket.send(message)
  except:
    discard

proc broadcastToRoom(roomName, message: string, exceptUser: string = "") {.async.} =
  ## Envoie un message a tous les membres d'un salon
  let members = roomManager.getRoomMembersExcept(roomName, exceptUser)
  let clients = clientManager.getClientsByUsernames(members)
  for client in clients:
    await sendToClient(client, message)

proc broadcastToAll(message: string, exceptSocket: AsyncSocket = nil) {.async.} =
  ## Envoie un message a tous les clients authentifies
  let clients = clientManager.getClientsExcept(exceptSocket)
  for client in clients:
    await sendToClient(client, message)

# ============================================================================
# Handlers de commandes
# ============================================================================

proc handleHello(client: Client, username: string): Future[string] {.async.} =
  ## Gere la commande HELLO
  if client.state != csConnected:
    return formatError(errInvalidFormat, "Already in auth process")

  # Verifier que l'utilisateur existe dans le registre
  if not userRegistry.userExists(username):
    return formatError(errUserNotFound, "User not registered")

  # Verifier qu'il n'est pas deja connecte
  if clientManager.isUsernameOnline(username):
    return formatError(errInvalidFormat, "User already online")

  # Demarrer le processus d'authentification
  let session = clientManager.startAuth(client.socket, username)
  return formatChallenge(session.challenge)

proc handleAuth(client: Client, signatureB64: string): Future[string] {.async.} =
  ## Gere la commande AUTH
  if client.state != csAuthPending:
    return formatError(errInvalidFormat, "No auth in progress")

  # SECURITE: Verifier si le client est bloque pour brute force
  if client.isAuthLocked():
    logger.log(lvlWarn, "Auth attempt blocked (brute force protection): " & client.remoteAddr)
    return formatError(errRateLimited, "Too many failed attempts, try again later")

  # Verifier que la session n'a pas expire
  if client.authSession.isSessionExpired():
    clientManager.failAuth(client.socket)
    client.recordAuthFailure()
    return formatError(errAuthFailed, "Challenge expired")

  # Recuperer la cle publique de l'utilisateur
  let pubKey = userRegistry.getUserPublicKey(client.username)
  if pubKey.len == 0:
    clientManager.failAuth(client.socket)
    client.recordAuthFailure()
    logger.log(lvlWarn, "Auth failed (user not found): " & client.username & " from " & client.remoteAddr)
    return formatError(errAuthFailed, "User not found")

  # Verifier la signature
  if not verifySignature(pubKey, client.authSession.challenge, signatureB64):
    clientManager.failAuth(client.socket)
    client.recordAuthFailure()
    logger.log(lvlWarn, "Auth failed (bad signature): " & client.username & " from " & client.remoteAddr)
    return formatError(errAuthFailed, "Invalid signature")

  # Authentification reussie
  if not clientManager.completeAuth(client.socket):
    return formatError(errInvalidFormat, "Username conflict")

  client.resetAuthFailures()
  logger.log(lvlInfo, "User authenticated: " & client.username)

  # Notifier tous les autres utilisateurs
  await broadcastToAll(formatOnline(client.username), client.socket)

  return formatWelcome(client.username)

proc handleJoin(client: Client, roomName: string): Future[string] {.async.} =
  ## Gere la commande JOIN
  if not clientManager.isAuthenticated(client.socket):
    return formatError(errNotAuthenticated)

  if roomManager.isInRoom(roomName, client.username):
    return formatError(errAlreadyInRoom, roomName)

  discard roomManager.joinRoom(roomName, client.username)

  # Notifier les autres membres du salon
  let notif = formatJoined(roomName, client.username)
  await broadcastToRoom(roomName, notif, client.username)

  logger.log(lvlInfo, client.username & " joined " & roomName)
  return formatOk("JOIN " & roomName)

proc handleLeave(client: Client, roomName: string): Future[string] {.async.} =
  ## Gere la commande LEAVE
  if not clientManager.isAuthenticated(client.socket):
    return formatError(errNotAuthenticated)

  if not roomManager.isInRoom(roomName, client.username):
    return formatError(errNotInRoom, roomName)

  # Notifier avant de quitter
  let notif = formatLeft(roomName, client.username)
  await broadcastToRoom(roomName, notif, client.username)

  discard roomManager.leaveRoom(roomName, client.username)

  logger.log(lvlInfo, client.username & " left " & roomName)
  return formatOk("LEAVE " & roomName)

proc handleMsg(client: Client, roomName, content: string): Future[string] {.async.} =
  ## Gere la commande MSG
  if not clientManager.isAuthenticated(client.socket):
    return formatError(errNotAuthenticated)

  if not roomManager.isInRoom(roomName, client.username):
    return formatError(errNotInRoom, roomName)

  # Broadcaster le message aux autres membres
  let msg = formatRoom(roomName, client.username, content)
  await broadcastToRoom(roomName, msg, client.username)

  return formatOk("MSG")

proc handlePrivMsg(client: Client, targetUser, content: string): Future[string] {.async.} =
  ## Gere la commande PRIVMSG
  if not clientManager.isAuthenticated(client.socket):
    return formatError(errNotAuthenticated)

  let targetClient = clientManager.getClientByUsername(targetUser)
  if targetClient == nil:
    return formatError(errUserNotFound, targetUser)

  # Envoyer le message prive
  let msg = formatPriv(client.username, content)
  await sendToClient(targetClient, msg)

  return formatOk("PRIVMSG")

proc handleList(client: Client): Future[string] {.async.} =
  ## Gere la commande LIST
  if not clientManager.isAuthenticated(client.socket):
    return formatError(errNotAuthenticated)

  let rooms = roomManager.listRooms()
  return formatRoomList(rooms)

proc handleWho(client: Client, roomName: string): Future[string] {.async.} =
  ## Gere la commande WHO
  if not clientManager.isAuthenticated(client.socket):
    return formatError(errNotAuthenticated)

  if not roomManager.roomExists(roomName):
    return formatError(errRoomNotFound, roomName)

  let members = roomManager.getRoomMembers(roomName)
  return formatWhoList(roomName, members)

proc handleUsers(client: Client): Future[string] {.async.} =
  ## Gere la commande USERS
  if not clientManager.isAuthenticated(client.socket):
    return formatError(errNotAuthenticated)

  let users = clientManager.listOnlineUsers()
  return formatUserList(users)

proc handlePing(client: Client): Future[string] {.async.} =
  return formatPong()

proc handleQuit(client: Client): Future[string] {.async.} =
  return ""  # La deconnexion est geree par le caller

proc handleRegister(client: Client, username, pubKey, token: string): Future[string] {.async.} =
  ## Gere la commande REGISTER (auto-inscription avec token)
  # Pas besoin d'etre authentifie pour s'inscrire

  # Verifier que l'utilisateur n'existe pas deja
  if userRegistry.userExists(username):
    logger.log(lvlWarn, "Register failed (user exists): " & username & " from " & client.remoteAddr)
    return formatError(errUserExists, "Username already taken")

  # Valider le token
  if not tokenRegistry.validateToken(token):
    logger.log(lvlWarn, "Register failed (invalid token): " & username & " from " & client.remoteAddr)
    return formatError(errInvalidToken, "Invalid or expired token")

  # Enregistrer l'utilisateur
  if not userRegistry.registerUser(username, pubKey):
    return formatError(errUserExists, "Registration failed")

  logger.log(lvlInfo, "New user registered: " & username)
  return formatOk("REGISTER " & username)

# ============================================================================
# Dispatch des commandes
# ============================================================================

proc processCommand(client: Client, line: string): Future[string] {.async.} =
  ## Parse et execute une commande
  let cmd = parseCommand(line)

  case cmd.kind
  of cmdHello:
    return await handleHello(client, cmd.helloUsername)
  of cmdAuth:
    return await handleAuth(client, cmd.authSignature)
  of cmdRegister:
    return await handleRegister(client, cmd.regUsername, cmd.regPubKey, cmd.regToken)
  of cmdJoin:
    return await handleJoin(client, cmd.roomName)
  of cmdLeave:
    return await handleLeave(client, cmd.roomName)
  of cmdMsg:
    return await handleMsg(client, cmd.msgRoom, cmd.msgContent)
  of cmdPrivMsg:
    return await handlePrivMsg(client, cmd.privTarget, cmd.privContent)
  of cmdList:
    return await handleList(client)
  of cmdWho:
    return await handleWho(client, cmd.roomName)
  of cmdUsers:
    return await handleUsers(client)
  of cmdPing:
    return await handlePing(client)
  of cmdQuit:
    return await handleQuit(client)
  of cmdUnknown:
    return formatError(errUnknownCommand)

# ============================================================================
# Gestion des clients
# ============================================================================

proc handleClient(socket: AsyncSocket, remoteAddr: string) {.async.} =
  ## Gere la connexion d'un client
  let client = clientManager.addClient(socket, remoteAddr)
  logger.log(lvlInfo, "New connection from " & remoteAddr)

  try:
    while true:
      let line = await socket.recvLine()
      if line.len == 0:
        break  # Connexion fermee

      if line.len > protocol.MaxLineLength:
        await sendToClient(client, formatError(errInvalidFormat, "Line too long"))
        continue

      # SECURITE: Rate limiting
      if not client.checkRateLimit(config.rateLimit):
        await sendToClient(client, formatError(errRateLimited, "Too many requests"))
        continue

      clientManager.updateActivity(socket)

      let response = await processCommand(client, line)
      if response.len > 0:
        await sendToClient(client, response)

      # Commande QUIT
      let cmd = parseCommand(line)
      if cmd.kind == cmdQuit:
        break

  except:
    logger.log(lvlError, "Error with client " & remoteAddr & ": " & getCurrentExceptionMsg())

  # Nettoyage a la deconnexion
  let username = clientManager.removeClient(socket)
  if username.len > 0:
    # Notifier les salons
    let leftRooms = roomManager.removeUserFromAllRooms(username)
    for roomName in leftRooms:
      let notif = formatLeft(roomName, username)
      await broadcastToRoom(roomName, notif)

    # Notifier tout le monde
    await broadcastToAll(formatQuitNotif(username))
    logger.log(lvlInfo, "User disconnected: " & username)
  else:
    logger.log(lvlInfo, "Anonymous disconnect from " & remoteAddr)

  socket.close()

# ============================================================================
# Serveur principal
# ============================================================================

proc runServer() {.async.} =
  ## Lance le serveur TLS
  var server = newAsyncSocket()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(config.port))
  server.listen()

  # Configuration SSL
  var sslContext = newContext(
    protSSLv23,  # Negociation automatique (preferera TLS 1.2+)
    verifyMode = CVerifyNone,
    certFile = config.certFile,
    keyFile = config.keyFile
  )

  logger.log(lvlInfo, "Murmur server started on port " & $config.port)
  logger.log(lvlInfo, "TLS enabled with certificate: " & config.certFile)

  while true:
    let (clientAddr, clientSocket) = await server.acceptAddr()

    # Verifier la limite de connexions
    if clientManager.getClientCount() >= config.maxConnections:
      logger.log(lvlWarn, "Connection rejected: max connections reached")
      clientSocket.close()
      continue

    # Wrapper TLS
    try:
      sslContext.wrapConnectedSocket(clientSocket, handshakeAsServer)
      asyncCheck handleClient(clientSocket, clientAddr)
    except:
      logger.log(lvlError, "TLS handshake failed for " & clientAddr)
      clientSocket.close()

# ============================================================================
# Point d'entree
# ============================================================================

proc main() =
  # Initialiser le logger
  logger = newConsoleLogger(fmtStr = "[$datetime] $levelname: ")
  addHandler(logger)

  # Charger la configuration
  let configPath = if paramCount() > 0: paramStr(1) else: "config.json"
  config = loadConfig(configPath)

  # Verifier les certificats
  if not fileExists(config.certFile) or not fileExists(config.keyFile):
    logger.log(lvlError, "TLS certificates not found!")
    logger.log(lvlError, "Run: nimble gencert")
    quit(1)

  # Charger le registre des utilisateurs
  userRegistry = loadUserRegistry(config.usersFile)
  logger.log(lvlInfo, "Loaded " & $len(userRegistry.users) & " registered users")

  # Charger le registre des tokens
  tokenRegistry = loadTokenRegistry(config.tokensFile)
  tokenRegistry.cleanExpiredTokens()
  logger.log(lvlInfo, "Loaded " & $len(tokenRegistry.tokens) & " valid invite tokens")

  # Initialiser les managers
  clientManager = newClientManager()
  roomManager = newRoomManager()

  # Lancer le serveur
  asyncCheck runServer()
  runForever()

when isMainModule:
  main()
