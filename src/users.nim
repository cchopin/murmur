## Module de gestion des utilisateurs connectes MURMUR
## Gere l'etat des connexions et les sessions actives

import std/[tables, asyncnet, times, sequtils, algorithm]
import auth

type
  ClientState* = enum
    csConnected       # Connecte mais pas authentifie
    csAuthPending     # En attente de reponse au challenge
    csAuthenticated   # Authentifie et pret

  ClientId* = int

  Client* = ref object
    id*: ClientId
    socket*: AsyncSocket
    username*: string
    state*: ClientState
    authSession*: AuthSession
    connectedAt*: Time
    lastActivity*: Time
    remoteAddr*: string
    # Securite: rate limiting et anti-brute force
    messageCount*: int
    messageWindowStart*: Time
    authFailures*: int
    lastAuthFailure*: Time

  ClientManager* = object
    clients*: Table[ClientId, Client]
    socketToId*: seq[(AsyncSocket, ClientId)]  # Mapping socket -> id
    usernameToId*: Table[string, ClientId]
    nextId: ClientId

proc newClientManager*(): ClientManager =
  result.clients = initTable[ClientId, Client]()
  result.socketToId = @[]
  result.usernameToId = initTable[string, ClientId]()
  result.nextId = 1

proc findIdBySocket(manager: ClientManager, socket: AsyncSocket): ClientId =
  ## Trouve l'ID d'un client par son socket
  for (s, id) in manager.socketToId:
    if s == socket:
      return id
  return 0

proc removeSocketMapping(manager: var ClientManager, socket: AsyncSocket) =
  ## Supprime le mapping socket -> id
  var idx = -1
  for i, (s, _) in manager.socketToId:
    if s == socket:
      idx = i
      break
  if idx >= 0:
    manager.socketToId.delete(idx)

const
  MaxAuthFailures* = 5
  AuthLockoutDuration* = initDuration(minutes = 5)
  RateLimitWindow* = initDuration(seconds = 1)

proc addClient*(manager: var ClientManager, socket: AsyncSocket, remoteAddr: string): Client =
  ## Ajoute un nouveau client connecte
  let now = getTime()
  let clientId = manager.nextId
  inc manager.nextId

  result = Client(
    id: clientId,
    socket: socket,
    username: "",
    state: csConnected,
    connectedAt: now,
    lastActivity: now,
    remoteAddr: remoteAddr,
    messageCount: 0,
    messageWindowStart: now,
    authFailures: 0,
    lastAuthFailure: Time()
  )
  manager.clients[clientId] = result
  manager.socketToId.add((socket, clientId))

proc checkRateLimit*(client: Client, maxRate: int): bool =
  ## Verifie si le client depasse le rate limit
  ## Retourne true si OK, false si rate limited
  let now = getTime()
  if now - client.messageWindowStart > RateLimitWindow:
    # Nouvelle fenetre
    client.messageCount = 1
    client.messageWindowStart = now
    return true
  else:
    inc client.messageCount
    return client.messageCount <= maxRate

proc recordAuthFailure*(client: Client) =
  ## Enregistre un echec d'authentification
  inc client.authFailures
  client.lastAuthFailure = getTime()

proc isAuthLocked*(client: Client): bool =
  ## Verifie si le client est bloque pour trop d'echecs d'auth
  if client.authFailures < MaxAuthFailures:
    return false
  # Verifier si le lockout a expire
  let now = getTime()
  if now - client.lastAuthFailure > AuthLockoutDuration:
    client.authFailures = 0
    return false
  return true

proc resetAuthFailures*(client: Client) =
  ## Remet a zero le compteur d'echecs apres une auth reussie
  client.authFailures = 0

proc removeClient*(manager: var ClientManager, socket: AsyncSocket): string =
  ## Supprime un client et retourne son username (vide si non authentifie)
  let clientId = manager.findIdBySocket(socket)
  if clientId == 0:
    return ""

  if clientId notin manager.clients:
    return ""

  let client = manager.clients[clientId]
  result = client.username

  if client.username.len > 0:
    manager.usernameToId.del(client.username)

  manager.clients.del(clientId)
  manager.removeSocketMapping(socket)

proc getClient*(manager: ClientManager, socket: AsyncSocket): Client =
  ## Retourne le client associe a un socket (nil si non trouve)
  let clientId = manager.findIdBySocket(socket)
  if clientId == 0:
    return nil
  return manager.clients.getOrDefault(clientId, nil)

proc getClientByUsername*(manager: ClientManager, username: string): Client =
  ## Retourne le client par son username (nil si non trouve)
  if username notin manager.usernameToId:
    return nil
  let clientId = manager.usernameToId[username]
  return manager.clients.getOrDefault(clientId, nil)

proc isUsernameOnline*(manager: ClientManager, username: string): bool =
  return username in manager.usernameToId

proc startAuth*(manager: var ClientManager, socket: AsyncSocket, username: string): AuthSession =
  ## Demarre le processus d'authentification pour un client
  let client = manager.getClient(socket)
  if client == nil:
    return AuthSession()

  client.authSession = createAuthSession(username)
  client.username = username
  client.state = csAuthPending
  return client.authSession

proc completeAuth*(manager: var ClientManager, socket: AsyncSocket): bool =
  ## Marque un client comme authentifie
  ## Retourne false si un autre client utilise deja ce username
  let client = manager.getClient(socket)
  if client == nil:
    return false

  # Verifier qu'aucun autre client n'utilise ce username
  if client.username in manager.usernameToId:
    let existingId = manager.usernameToId[client.username]
    if existingId != client.id:
      return false

  client.state = csAuthenticated
  client.authSession.authenticated = true
  manager.usernameToId[client.username] = client.id
  return true

proc failAuth*(manager: var ClientManager, socket: AsyncSocket) =
  ## Reinitialise l'etat d'authentification d'un client
  let client = manager.getClient(socket)
  if client != nil:
    client.state = csConnected
    client.username = ""
    client.authSession = AuthSession()

proc updateActivity*(manager: var ClientManager, socket: AsyncSocket) =
  ## Met a jour le timestamp de derniere activite
  let client = manager.getClient(socket)
  if client != nil:
    client.lastActivity = getTime()

proc isAuthenticated*(manager: ClientManager, socket: AsyncSocket): bool =
  let client = manager.getClient(socket)
  if client == nil:
    return false
  return client.state == csAuthenticated

proc getUsername*(manager: ClientManager, socket: AsyncSocket): string =
  let client = manager.getClient(socket)
  if client == nil:
    return ""
  return client.username

proc listOnlineUsers*(manager: ClientManager): seq[string] =
  ## Retourne la liste des utilisateurs connectes et authentifies
  result = toSeq(manager.usernameToId.keys)
  result.sort()

proc getClientCount*(manager: ClientManager): int =
  return manager.clients.len

proc getAuthenticatedCount*(manager: ClientManager): int =
  return manager.usernameToId.len

proc getAllClients*(manager: ClientManager): seq[Client] =
  ## Retourne tous les clients (pour broadcast, etc.)
  result = @[]
  for client in manager.clients.values:
    result.add(client)

proc getAuthenticatedClients*(manager: ClientManager): seq[Client] =
  ## Retourne uniquement les clients authentifies
  result = @[]
  for client in manager.clients.values:
    if client.state == csAuthenticated:
      result.add(client)

proc getClientsExcept*(manager: ClientManager, exceptSocket: AsyncSocket): seq[Client] =
  ## Retourne tous les clients authentifies sauf un
  let exceptId = manager.findIdBySocket(exceptSocket)
  result = @[]
  for id, client in manager.clients:
    if id != exceptId and client.state == csAuthenticated:
      result.add(client)

proc getClientsByUsernames*(manager: ClientManager, usernames: seq[string]): seq[Client] =
  ## Retourne les clients correspondant a une liste de usernames
  result = @[]
  for username in usernames:
    if username in manager.usernameToId:
      let clientId = manager.usernameToId[username]
      let client = manager.clients.getOrDefault(clientId, nil)
      if client != nil:
        result.add(client)
