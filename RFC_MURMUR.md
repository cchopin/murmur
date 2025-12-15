# MURMUR Protocol Specification

**Version:** 1.0
**Status:** Stable
**Last Updated:** December 2025

---

## Table of Contents

1. [Overview](#1-overview)
2. [Transport Layer](#2-transport-layer)
3. [Message Format](#3-message-format)
4. [Authentication](#4-authentication)
5. [Commands Reference](#5-commands-reference)
6. [Server Messages](#6-server-messages)
7. [Error Codes](#7-error-codes)
8. [Security Considerations](#8-security-considerations)
9. [Client Implementation Checklist](#9-client-implementation-checklist)

---

## 1. Overview

MURMUR is a text-based chat protocol designed for secure real-time communication. It provides public room messaging and private user-to-user messaging with cryptographic authentication.

### 1.1 Design Principles

| Principle | Description |
|-----------|-------------|
| Simplicity | Human-readable text protocol |
| Security | TLS transport encryption, challenge-response authentication |
| Ephemerality | No server-side message persistence |
| Minimal State | Stateless command processing |

### 1.2 Terminology

| Term | Definition |
|------|------------|
| Client | Application connecting to a MURMUR server |
| Server | MURMUR service accepting client connections |
| Room | Named channel for group communication |
| User | Authenticated identity on the server |
| Session | Authenticated connection between client and server |

---

## 2. Transport Layer

### 2.1 Connection Parameters

| Parameter | Value |
|-----------|-------|
| Protocol | TCP |
| Default Port | 6697 |
| Encryption | TLS 1.2 minimum (mandatory) |
| Line Terminator | CRLF (`\r\n`) |

### 2.2 Connection Lifecycle

```
TCP Connect → TLS Handshake → Authentication → Active Session → Disconnect
```

A client MUST complete TLS negotiation before sending any protocol messages. Authentication MUST be completed before accessing chat functionality.

### 2.3 Timeouts and Limits

| Parameter | Value |
|-----------|-------|
| Maximum line length | 4096 bytes |
| Maximum message content | 2048 bytes |
| Maximum username length | 32 characters |
| Maximum room name length | 64 characters |
| Challenge validity | 30 seconds |
| Default rate limit | 10 messages/second |

---

## 3. Message Format

### 3.1 General Syntax

```
COMMAND [ARGUMENT1] [ARGUMENT2] [...]\r\n
```

- All messages MUST be UTF-8 encoded
- All messages MUST terminate with CRLF
- Commands are case-insensitive
- Arguments are space-separated
- Message content (final argument) extends to end of line

### 3.2 Data Types

| Type | Format | Constraints |
|------|--------|-------------|
| Username | `[a-zA-Z0-9_]+` | 1-32 characters |
| Room Name | `[#&][a-zA-Z0-9_-]+` | 2-64 characters, lowercase normalized |
| Base64 | RFC 4648 standard encoding | Variable length |
| Message Text | UTF-8 string | 1-2048 bytes |

### 3.3 Room Naming

- Room names MUST begin with `#` or `&`
- Room names are normalized to lowercase
- Valid characters after prefix: `a-z`, `A-Z`, `0-9`, `_`, `-`

---

## 4. Authentication

MURMUR implements challenge-response authentication using BLAKE2b-256. This mechanism verifies possession of a private key without transmission.

### 4.1 Key Derivation

The public key is derived from the private key:

```
public_key = BLAKE2b-256(private_key)
```

Both keys are stored and transmitted as base64-encoded strings.

### 4.2 Authentication Sequence

```
Client                              Server
  |                                    |
  |  -------- HELLO username --------> |
  |                                    |  (verify user exists)
  |  <------ CHALLENGE nonce --------- |
  |                                    |
  |  -------- AUTH signature --------> |
  |                                    |  (verify signature)
  |  <-------- WELCOME username ------ |
  |                                    |
```

### 4.3 Signature Computation

```
public_key = BLAKE2b-256(Base64Decode(private_key_b64))
signature = Base64Encode(BLAKE2b-256(Base64Decode(nonce_b64) || public_key))
```

Where `||` denotes byte concatenation.

### 4.4 Authentication Failure Handling

- Invalid signature: `ERROR AUTH_FAILED`
- Expired challenge (>30s): `ERROR AUTH_FAILED`
- Rate limiting: After 5 consecutive failures, 5-minute lockout period

---

## 5. Commands Reference

All commands require authentication unless otherwise noted.

### 5.1 Authentication Commands

#### HELLO

Initiates authentication. Does not require prior authentication.

| | |
|---|---|
| Syntax | `HELLO <username>` |
| Success | `CHALLENGE <nonce_b64>` |
| Errors | `USER_NOT_FOUND`, `INVALID_FORMAT` |

#### AUTH

Completes authentication with computed signature. Does not require prior authentication.

| | |
|---|---|
| Syntax | `AUTH <signature_b64>` |
| Success | `WELCOME <username>` |
| Errors | `AUTH_FAILED`, `INVALID_FORMAT`, `RATE_LIMITED` |

#### REGISTER

Registers a new user account using an invitation token. Does not require prior authentication. The client generates their own key pair locally and sends the public key with a valid invitation token.

| | |
|---|---|
| Syntax | `REGISTER <username> <public_key_b64> <token>` |
| Success | `OK REGISTER <username>` |
| Errors | `USER_EXISTS`, `INVALID_TOKEN`, `INVALID_FORMAT` |

Registration workflow:
1. Administrator generates invitation token on server
2. Administrator sends token to new user (out-of-band)
3. User generates key pair locally
4. User connects to server and sends REGISTER command
5. Server validates token (single-use, expires after 7 days)
6. User can now authenticate with HELLO/AUTH

---

### 5.2 Room Commands

#### JOIN

Joins a room. Creates the room if it does not exist.

| | |
|---|---|
| Syntax | `JOIN <room>` |
| Success | `OK JOIN <room>` |
| Errors | `NOT_AUTHENTICATED`, `ALREADY_IN_ROOM`, `INVALID_FORMAT` |
| Broadcast | `JOINED <room> <username>` to room members |

#### LEAVE

Leaves a room.

| | |
|---|---|
| Syntax | `LEAVE <room>` |
| Success | `OK LEAVE <room>` |
| Errors | `NOT_AUTHENTICATED`, `NOT_IN_ROOM` |
| Broadcast | `LEFT <room> <username>` to room members |

#### MSG

Sends a message to a room. Sender must be a member.

| | |
|---|---|
| Syntax | `MSG <room> <message>` |
| Success | `OK MSG` |
| Errors | `NOT_AUTHENTICATED`, `NOT_IN_ROOM` |
| Broadcast | `ROOM <room> <sender> <message>` to other room members |

#### WHO

Retrieves member list of a room.

| | |
|---|---|
| Syntax | `WHO <room>` |
| Success | `WHOLIST <room> [<user1> <user2> ...]` |
| Errors | `NOT_AUTHENTICATED`, `ROOM_NOT_FOUND` |

---

### 5.3 Private Messaging

#### PRIVMSG

Sends a private message to a connected user.

| | |
|---|---|
| Syntax | `PRIVMSG <username> <message>` |
| Success | `OK PRIVMSG` |
| Errors | `NOT_AUTHENTICATED`, `USER_NOT_FOUND` |
| Delivery | `PRIV <sender> <message>` to recipient |

---

### 5.4 Information Commands

#### LIST

Retrieves list of active rooms.

| | |
|---|---|
| Syntax | `LIST` |
| Response | `ROOMLIST [<room1> <room2> ...]` |
| Errors | `NOT_AUTHENTICATED` |

#### USERS

Retrieves list of all connected users.

| | |
|---|---|
| Syntax | `USERS` |
| Response | `USERLIST [<user1> <user2> ...]` |
| Errors | `NOT_AUTHENTICATED` |

---

### 5.5 Utility Commands

#### PING

Tests connection liveness.

| | |
|---|---|
| Syntax | `PING` |
| Response | `PONG` |

#### QUIT

Initiates graceful disconnection.

| | |
|---|---|
| Syntax | `QUIT` |
| Response | Connection closed by server |
| Broadcast | `QUIT <username>` to all connected users |

---

## 6. Server Messages

### 6.1 Response Messages

| Message | Format | Description |
|---------|--------|-------------|
| OK | `OK [info]` | Command succeeded |
| ERROR | `ERROR <code> [message]` | Command failed |
| CHALLENGE | `CHALLENGE <nonce_b64>` | Authentication challenge |
| WELCOME | `WELCOME <username>` | Authentication successful |
| PONG | `PONG` | Response to PING |

### 6.2 Notification Messages

These messages are sent asynchronously to relevant clients.

| Message | Format | Recipients |
|---------|--------|------------|
| ROOM | `ROOM <room> <sender> <message>` | Room members except sender |
| PRIV | `PRIV <sender> <message>` | Target user |
| JOINED | `JOINED <room> <username>` | Room members except joiner |
| LEFT | `LEFT <room> <username>` | Room members |
| ONLINE | `ONLINE <username>` | All authenticated users except the new user |
| QUIT | `QUIT <username>` | All authenticated users |

### 6.3 List Messages

| Message | Format |
|---------|--------|
| ROOMLIST | `ROOMLIST [<room1> <room2> ...]` |
| USERLIST | `USERLIST [<user1> <user2> ...]` |
| WHOLIST | `WHOLIST <room> [<user1> <user2> ...]` |

Empty lists omit the user/room arguments.

---

## 7. Error Codes

| Code | Description |
|------|-------------|
| `UNKNOWN_COMMAND` | Command not recognized |
| `NOT_AUTHENTICATED` | Command requires authentication |
| `AUTH_FAILED` | Authentication failed (invalid signature or expired challenge) |
| `USER_NOT_FOUND` | User not registered or not connected |
| `USER_EXISTS` | Username already registered (REGISTER) |
| `INVALID_TOKEN` | Invitation token invalid or expired (REGISTER) |
| `ROOM_NOT_FOUND` | Room does not exist |
| `ALREADY_IN_ROOM` | User already member of room |
| `NOT_IN_ROOM` | User not member of room |
| `INVALID_FORMAT` | Malformed command or invalid arguments |
| `RATE_LIMITED` | Rate limit exceeded |

---

## 8. Security Considerations

### 8.1 Transport Security

- TLS 1.2 or higher is mandatory
- Server certificate validation is recommended for production deployments
- Self-signed certificates may be used for development environments

### 8.2 Authentication Security

- Private keys are never transmitted
- Challenges are cryptographically random (32 bytes from secure random source)
- Challenge validity is time-bounded (30 seconds)
- Failed attempts trigger rate limiting (5 failures = 5 minute lockout)
- All authentication failures are logged with source IP

### 8.3 Input Validation

- All input lengths are validated against defined limits
- Username format is strictly validated (alphanumeric and underscore only)
- Room names are validated and normalized
- Message content length is enforced

### 8.4 Rate Limiting

- Per-connection message rate limiting (configurable, default 10/second)
- Authentication attempt rate limiting (5 attempts per 5 minutes)

### 8.5 Data Handling

- No message persistence
- No conversation history
- User presence data is transient

---

## 9. Client Implementation Checklist

### 9.1 Connection Management

- [ ] Establish TCP connection to server host and port
- [ ] Initiate TLS handshake
- [ ] Implement connection timeout handling
- [ ] Implement reconnection with exponential backoff
- [ ] Handle connection errors gracefully

### 9.2 Protocol Handling

- [ ] Buffer incoming data until CRLF delimiter
- [ ] Parse messages by splitting on first space(s)
- [ ] Send all commands with CRLF terminator
- [ ] Enforce maximum line length (4096 bytes)
- [ ] Handle UTF-8 encoding correctly

### 9.3 Authentication

- [ ] Securely store private key
- [ ] Implement BLAKE2b-256 hashing
- [ ] Derive public key from private key
- [ ] Send HELLO with username
- [ ] Parse CHALLENGE response and extract nonce
- [ ] Compute signature per section 4.3
- [ ] Send AUTH with signature
- [ ] Handle WELCOME (success) and ERROR (failure)
- [ ] Track authentication state

### 9.4 Room Operations

- [ ] Send JOIN command with room name
- [ ] Send LEAVE command with room name
- [ ] Send MSG command with room and message
- [ ] Send WHO command to get member list
- [ ] Send LIST command to get room list
- [ ] Track joined rooms locally

### 9.5 Private Messaging

- [ ] Send PRIVMSG command with target user and message
- [ ] Handle PRIV notifications for incoming messages

### 9.6 User Presence

- [ ] Send USERS command to get online user list
- [ ] Handle ONLINE notifications (user connected)
- [ ] Handle QUIT notifications (user disconnected)
- [ ] Maintain local cache of online users

### 9.7 Event Processing

- [ ] Handle ROOM notifications (room message received)
- [ ] Handle PRIV notifications (private message received)
- [ ] Handle JOINED notifications (user joined room)
- [ ] Handle LEFT notifications (user left room)
- [ ] Handle ONLINE notifications (user connected)
- [ ] Handle QUIT notifications (user disconnected)
- [ ] Update local state based on notifications

### 9.8 Error Handling

- [ ] Parse ERROR responses and extract code
- [ ] Handle each error code appropriately
- [ ] Display user-friendly error messages
- [ ] Handle rate limiting (back off sending)

### 9.9 Connection Lifecycle

- [ ] Send PING periodically to detect connection loss
- [ ] Handle PONG responses
- [ ] Send QUIT before intentional disconnect
- [ ] Clean up resources on disconnect

### 9.10 Testing Verification

- [ ] Verify authentication succeeds with valid credentials
- [ ] Verify authentication fails with invalid credentials
- [ ] Verify room join/leave/message cycle
- [ ] Verify private message delivery
- [ ] Verify presence notifications received
- [ ] Verify error handling for each error code
- [ ] Verify reconnection after disconnect
- [ ] Verify rate limiting behavior

---

## Appendix A: Message Summary

### Client Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `HELLO` | `<username>` | Initiate authentication |
| `AUTH` | `<signature_b64>` | Complete authentication |
| `REGISTER` | `<username> <pubkey_b64> <token>` | Register new account |
| `JOIN` | `<room>` | Join room |
| `LEAVE` | `<room>` | Leave room |
| `MSG` | `<room> <message>` | Send room message |
| `PRIVMSG` | `<username> <message>` | Send private message |
| `LIST` | | Get room list |
| `WHO` | `<room>` | Get room members |
| `USERS` | | Get online users |
| `PING` | | Test connection |
| `QUIT` | | Disconnect |

### Server Messages

| Message | Arguments | Description |
|---------|-----------|-------------|
| `OK` | `[info]` | Success |
| `ERROR` | `<code> [message]` | Failure |
| `CHALLENGE` | `<nonce_b64>` | Auth challenge |
| `WELCOME` | `<username>` | Auth success |
| `PONG` | | Ping response |
| `ROOM` | `<room> <user> <message>` | Room message |
| `PRIV` | `<user> <message>` | Private message |
| `JOINED` | `<room> <user>` | User joined room |
| `LEFT` | `<room> <user>` | User left room |
| `ONLINE` | `<user>` | User connected |
| `QUIT` | `<user>` | User disconnected |
| `ROOMLIST` | `[rooms...]` | Room list |
| `USERLIST` | `[users...]` | User list |
| `WHOLIST` | `<room> [users...]` | Room members |

---

## Appendix B: Revision History

| Version | Date | Description |
|---------|------|-------------|
| 1.0 | December 2025 | Initial stable release |

---

*End of specification.*
