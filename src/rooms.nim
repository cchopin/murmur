## Module de gestion des salons MURMUR
## Gere la creation, les membres et les messages des salons

import std/[tables, sets, sequtils, algorithm]

type
  Room* = object
    name*: string
    members*: HashSet[string]  # usernames des membres
    topic*: string
    createdBy*: string

  RoomManager* = object
    rooms*: Table[string, Room]

proc newRoomManager*(): RoomManager =
  result.rooms = initTable[string, Room]()

proc roomExists*(manager: RoomManager, roomName: string): bool =
  return roomName in manager.rooms

proc createRoom*(manager: var RoomManager, roomName, creator: string): bool =
  ## Cree un nouveau salon s'il n'existe pas
  ## Retourne true si cree, false si deja existant
  if manager.roomExists(roomName):
    return false

  var room = Room(
    name: roomName,
    members: initHashSet[string](),
    topic: "",
    createdBy: creator
  )
  manager.rooms[roomName] = room
  return true

proc deleteRoom*(manager: var RoomManager, roomName: string): bool =
  ## Supprime un salon s'il existe et est vide
  if not manager.roomExists(roomName):
    return false
  if manager.rooms[roomName].members.len > 0:
    return false
  manager.rooms.del(roomName)
  return true

proc joinRoom*(manager: var RoomManager, roomName, username: string): bool =
  ## Ajoute un utilisateur a un salon
  ## Cree le salon s'il n'existe pas
  ## Retourne false si l'utilisateur est deja dans le salon
  if not manager.roomExists(roomName):
    discard manager.createRoom(roomName, username)

  if username in manager.rooms[roomName].members:
    return false

  manager.rooms[roomName].members.incl(username)
  return true

proc leaveRoom*(manager: var RoomManager, roomName, username: string): bool =
  ## Retire un utilisateur d'un salon
  ## Retourne false si le salon n'existe pas ou si l'utilisateur n'y est pas
  if not manager.roomExists(roomName):
    return false

  if username notin manager.rooms[roomName].members:
    return false

  manager.rooms[roomName].members.excl(username)

  # Supprimer le salon s'il est vide
  if manager.rooms[roomName].members.len == 0:
    manager.rooms.del(roomName)

  return true

proc isInRoom*(manager: RoomManager, roomName, username: string): bool =
  ## Verifie si un utilisateur est dans un salon
  if not manager.roomExists(roomName):
    return false
  return username in manager.rooms[roomName].members

proc getRoomMembers*(manager: RoomManager, roomName: string): seq[string] =
  ## Retourne la liste des membres d'un salon
  if not manager.roomExists(roomName):
    return @[]
  result = toSeq(manager.rooms[roomName].members)
  result.sort()

proc getRoomMembersExcept*(manager: RoomManager, roomName, exceptUser: string): seq[string] =
  ## Retourne la liste des membres d'un salon sauf un utilisateur
  ## Utile pour broadcaster a tous sauf l'emetteur
  if not manager.roomExists(roomName):
    return @[]
  result = @[]
  for member in manager.rooms[roomName].members:
    if member != exceptUser:
      result.add(member)
  result.sort()

proc listRooms*(manager: RoomManager): seq[string] =
  ## Retourne la liste de tous les salons
  result = toSeq(manager.rooms.keys)
  result.sort()

proc listRoomsWithCount*(manager: RoomManager): seq[(string, int)] =
  ## Retourne la liste des salons avec leur nombre de membres
  result = @[]
  for name, room in manager.rooms:
    result.add((name, room.members.len))
  result.sort(proc(a, b: (string, int)): int = cmp(a[0], b[0]))

proc getUserRooms*(manager: RoomManager, username: string): seq[string] =
  ## Retourne la liste des salons auxquels appartient un utilisateur
  result = @[]
  for name, room in manager.rooms:
    if username in room.members:
      result.add(name)
  result.sort()

proc removeUserFromAllRooms*(manager: var RoomManager, username: string): seq[string] =
  ## Retire un utilisateur de tous les salons
  ## Retourne la liste des salons quittes
  result = @[]
  var emptyRooms: seq[string] = @[]

  for name, room in manager.rooms.mpairs:
    if username in room.members:
      room.members.excl(username)
      result.add(name)
      if room.members.len == 0:
        emptyRooms.add(name)

  # Supprimer les salons vides
  for name in emptyRooms:
    manager.rooms.del(name)

proc setTopic*(manager: var RoomManager, roomName, topic: string): bool =
  ## Definit le sujet d'un salon
  if not manager.roomExists(roomName):
    return false
  manager.rooms[roomName].topic = topic
  return true

proc getTopic*(manager: RoomManager, roomName: string): string =
  ## Retourne le sujet d'un salon
  if not manager.roomExists(roomName):
    return ""
  return manager.rooms[roomName].topic
