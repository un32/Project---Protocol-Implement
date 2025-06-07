# SGCP (Secure Group Chat Protocol) Implementation

## Overview
This is a complete implementation of the Secure Group Chat Protocol (SGCP) as specified in the project requirements. The implementation includes both server and client components with a stateful protocol following the DFA (Deterministic Finite Automata) design.

## Features

- **Stateful Protocol**: Full DFA enforcement and state validation on client and server
- **Connection Management**: Handshake using `MSG_HELLO` and `MSG_CAPABILITIES`
- **Authentication**: Username/password with session tokens
- **Group Chat**: Join, leave, and broadcast messages within groups
- **Error Handling**: Comprehensive protocol error codes and malformed message rejection
- **Standard Library Only**: No external dependencies

## System Requirements

- **Python**: 3.7 or higher
- **Platform**: Linux, macOS, or Windows (WSL compatible)
- **Dependencies**: None (uses only Python standard library)

 ## File Structure 
sgcp-implementation/
 ```
├── server.py # SGCP server
├── client.py # SGCP client (CLI user interface)
├── sgcp_protocol.py # Protocol constants, enums, and message logic
└── README.md # Documentation

```
## Installation & Setup

1. **Clone or download this repository**
2. Ensure all files (`server.py`, `client.py`, `sgcp_protocol.py`, `README.md`) are in the same directory
3. **Verify Python installation:**
    ```sh
    python3 --version
    # Should show Python 3.7 or higher
    ```

---

## Running the Server

Open a terminal and run:
```sh
python3 server.py --host localhost --port 8888
# Or use a custom host/port if needed
```

## Running the Server
Open another terminal and run:
```sh
python3 client.py --host localhost --port 8888
# Or connect to a custom host/port if needed
```

## Client Commands
Once connected, use the following commands at the client prompt:

- login <username> <password> – Authenticate with the server
- list – List all available groups
- join <group_id> – Join a group (e.g., join 1)
- leave <group_id> – Leave a group
- chat <group_id> <message> – Send a message to a group (e.g., chat 1 Hello!)
- quit – Disconnect and exit

## Default User Accounts

The server comes with these pre-configured users:

| Username | Password |
|----------|----------|
| admin    | admin    |
| user1    | password |
| user2    | password |

## Example Usage

### 1. Start the server (Terminal 1)
```sh
python3 server.py
# Output: SGCP Server started on localhost:8888
```

### 2. Start the first client (Terminal 2)
```sh
python3 client.py
> login admin admin
> list
> join 1
> chat 1 Hello everyone!
```

### 3. Start a second client (Terminal 3)
```sh
python3 client.py
> login user1 password
> join 1
> chat 1 Hi admin!
# [Group 1] User 1: Hello everyone!  (receives admin's message)
```

## Troubleshooting
- **"Address already in use" error:** Use a different port, e.g., python3 server.py --port 9001
- **Client can't connect:** Make sure server is running, check host/port and firewall settings
- **Authentication fails:** Double-check username and password
- **No messages received:** Ensure both clients have joined the same group

## Protocol Compliance
- 16-byte, big-endian headers; UTF-8 encoded text
- All core message types and protocol states implemented
- Full DFA-based protocol state validation
- Comprehensive error code support
- Group-based chat and user isolation

## Future Enhancements
- End-to-end encryption (AES-GCM)
- File transfer support
- Custom group creation/removal
- Advanced permissions (admins, moderators)
= Web or graphical client


