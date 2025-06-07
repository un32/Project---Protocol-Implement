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

