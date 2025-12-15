## Module de protocole MURMUR
## Gere le parsing des commandes et la serialisation des reponses

import std/[strutils, strformat]

type
  CommandKind* = enum
    cmdHello      # HELLO <username>
    cmdAuth       # AUTH <signature_base64>
    cmdRegister   # REGISTER <username> <pubkey_base64> <token>
    cmdJoin       # JOIN <room>
    cmdLeave      # LEAVE <room>
    cmdMsg        # MSG <room> <message>
    cmdPrivMsg    # PRIVMSG <user> <message>
    cmdList       # LIST
    cmdWho        # WHO <room>
    cmdUsers      # USERS
    cmdQuit       # QUIT
    cmdPing       # PING
    cmdUnknown    # Commande inconnue

  Command* = object
    case kind*: CommandKind
    of cmdHello:
      helloUsername*: string
    of cmdAuth:
      authSignature*: string
    of cmdRegister:
      regUsername*: string
      regPubKey*: string
      regToken*: string
    of cmdJoin, cmdLeave, cmdWho:
      roomName*: string
    of cmdMsg:
      msgRoom*: string
      msgContent*: string
    of cmdPrivMsg:
      privTarget*: string
      privContent*: string
    of cmdList, cmdUsers, cmdQuit, cmdPing, cmdUnknown:
      discard

  ResponseKind* = enum
    respOk          # OK <info>
    respError       # ERROR <code> <message>
    respChallenge   # CHALLENGE <nonce_base64>
    respWelcome     # WELCOME <username>
    respRoom        # ROOM <room> <user> <message>
    respPriv        # PRIV <user> <message>
    respJoined      # JOINED <room> <user>
    respLeft        # LEFT <room> <user>
    respRoomList    # ROOMLIST <room1> <room2> ...
    respUserList    # USERLIST <user1> <user2> ...
    respWhoList     # WHOLIST <room> <user1> <user2> ...
    respPong        # PONG
    respOnline      # ONLINE <user>
    respQuit        # QUIT <user>

  ErrorCode* = enum
    errUnknownCommand = "UNKNOWN_COMMAND"
    errNotAuthenticated = "NOT_AUTHENTICATED"
    errAuthFailed = "AUTH_FAILED"
    errUserNotFound = "USER_NOT_FOUND"
    errRoomNotFound = "ROOM_NOT_FOUND"
    errAlreadyInRoom = "ALREADY_IN_ROOM"
    errNotInRoom = "NOT_IN_ROOM"
    errInvalidFormat = "INVALID_FORMAT"
    errRateLimited = "RATE_LIMITED"
    errInvalidToken = "INVALID_TOKEN"
    errUserExists = "USER_EXISTS"

const
  MaxLineLength* = 4096
  MaxMessageLength* = 2048
  MaxUsernameLength* = 32
  MaxRoomNameLength* = 64

proc parseCommand*(line: string): Command =
  ## Parse une ligne de commande envoyee par le client
  let trimmed = line.strip()
  if trimmed.len == 0:
    return Command(kind: cmdUnknown)

  let parts = trimmed.split(' ', maxsplit = 1)
  let cmd = parts[0].toUpperAscii()
  let args = if parts.len > 1: parts[1] else: ""

  case cmd
  of "HELLO":
    if args.len == 0 or args.len > MaxUsernameLength:
      return Command(kind: cmdUnknown)
    # Valide que le username ne contient que des caracteres alphanumeriques et _
    for c in args:
      if c notin {'a'..'z', 'A'..'Z', '0'..'9', '_'}:
        return Command(kind: cmdUnknown)
    return Command(kind: cmdHello, helloUsername: args)

  of "AUTH":
    if args.len == 0:
      return Command(kind: cmdUnknown)
    return Command(kind: cmdAuth, authSignature: args)

  of "REGISTER":
    # Format: REGISTER <username> <pubkey_base64> <token>
    let regParts = args.split(' ')
    if regParts.len != 3:
      return Command(kind: cmdUnknown)
    let username = regParts[0]
    let pubKey = regParts[1]
    let token = regParts[2]
    # Valider le username
    if username.len == 0 or username.len > MaxUsernameLength:
      return Command(kind: cmdUnknown)
    for c in username:
      if c notin {'a'..'z', 'A'..'Z', '0'..'9', '_'}:
        return Command(kind: cmdUnknown)
    return Command(kind: cmdRegister, regUsername: username, regPubKey: pubKey, regToken: token)

  of "JOIN":
    if args.len == 0 or args.len > MaxRoomNameLength:
      return Command(kind: cmdUnknown)
    # Valide le nom du salon (commence par # ou &)
    if args[0] notin {'#', '&'}:
      return Command(kind: cmdUnknown)
    for c in args[1..^1]:
      if c notin {'a'..'z', 'A'..'Z', '0'..'9', '_', '-'}:
        return Command(kind: cmdUnknown)
    return Command(kind: cmdJoin, roomName: args.toLowerAscii())

  of "LEAVE":
    if args.len == 0:
      return Command(kind: cmdUnknown)
    return Command(kind: cmdLeave, roomName: args.toLowerAscii())

  of "MSG":
    let msgParts = args.split(' ', maxsplit = 1)
    if msgParts.len < 2:
      return Command(kind: cmdUnknown)
    let room = msgParts[0].toLowerAscii()
    let content = msgParts[1]
    if content.len > MaxMessageLength:
      return Command(kind: cmdUnknown)
    return Command(kind: cmdMsg, msgRoom: room, msgContent: content)

  of "PRIVMSG":
    let privParts = args.split(' ', maxsplit = 1)
    if privParts.len < 2:
      return Command(kind: cmdUnknown)
    let target = privParts[0]
    let content = privParts[1]
    if content.len > MaxMessageLength:
      return Command(kind: cmdUnknown)
    return Command(kind: cmdPrivMsg, privTarget: target, privContent: content)

  of "LIST":
    return Command(kind: cmdList)

  of "WHO":
    if args.len == 0:
      return Command(kind: cmdUnknown)
    return Command(kind: cmdWho, roomName: args.toLowerAscii())

  of "USERS":
    return Command(kind: cmdUsers)

  of "QUIT":
    return Command(kind: cmdQuit)

  of "PING":
    return Command(kind: cmdPing)

  else:
    return Command(kind: cmdUnknown)

# ============================================================================
# Formatage des reponses serveur -> client
# ============================================================================

proc formatOk*(info: string = ""): string =
  if info.len > 0:
    result = &"OK {info}\r\n"
  else:
    result = "OK\r\n"

proc formatError*(code: ErrorCode, message: string = ""): string =
  if message.len > 0:
    result = &"ERROR {code} {message}\r\n"
  else:
    result = &"ERROR {code}\r\n"

proc formatChallenge*(nonce: string): string =
  ## nonce doit etre encode en base64
  result = &"CHALLENGE {nonce}\r\n"

proc formatWelcome*(username: string): string =
  result = &"WELCOME {username}\r\n"

proc formatRoom*(room, user, message: string): string =
  result = &"ROOM {room} {user} {message}\r\n"

proc formatPriv*(fromUser, message: string): string =
  result = &"PRIV {fromUser} {message}\r\n"

proc formatJoined*(room, user: string): string =
  result = &"JOINED {room} {user}\r\n"

proc formatLeft*(room, user: string): string =
  result = &"LEFT {room} {user}\r\n"

proc formatRoomList*(rooms: seq[string]): string =
  if rooms.len == 0:
    result = "ROOMLIST\r\n"
  else:
    result = &"ROOMLIST {rooms.join(\" \")}\r\n"

proc formatUserList*(users: seq[string]): string =
  if users.len == 0:
    result = "USERLIST\r\n"
  else:
    result = &"USERLIST {users.join(\" \")}\r\n"

proc formatWhoList*(room: string, users: seq[string]): string =
  if users.len == 0:
    result = &"WHOLIST {room}\r\n"
  else:
    result = &"WHOLIST {room} {users.join(\" \")}\r\n"

proc formatPong*(): string =
  result = "PONG\r\n"

proc formatOnline*(user: string): string =
  result = &"ONLINE {user}\r\n"

proc formatQuitNotif*(user: string): string =
  result = &"QUIT {user}\r\n"
