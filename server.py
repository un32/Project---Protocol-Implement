# server.py

import socket
import threading
import json
import struct
import time
import argparse
import hashlib
import secrets

from sgcp_protocol import (
    PROTOCOL_VERSION, HEADER_SIZE, DEFAULT_PORT,
    MessageType, MessageFlags, ErrorCode, ProtocolState, Capabilities,
    SGCPMessage
)

class SGCPServer:
    # SGCP Server Implementation

    def __init__(self, host='localhost', port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.socket = None
        self.clients = {}  # socket: dict
        self.groups = {}
        self.users = {
            'admin': {'password': self._hash_password('admin'), 'user_id': 1},
            'user1': {'password': self._hash_password('password'), 'user_id': 2},
            'user2': {'password': self._hash_password('password'), 'user_id': 3}
        }
        self.next_user_id = 4
        self.next_group_id = 1
        self.sequence_counter = 0
        self.running = False

        # Create default public group
        self.groups[1] = {
            'name': 'General',
            'members': set(),
            'public': True,
            'creator': 1
        }

    def _hash_password(self, password: str) -> str:
       # Hash password with SHA-256
        return hashlib.sha256(password.encode()).hexdigest()

    def _generate_session_token(self) -> int:
        # Increment and wrap sequence number (used for message IDs)
        return secrets.randbits(32)

    def _get_next_sequence(self) -> int:
        # Increment and wrap sequence number (used for message IDs)
        self.sequence_counter = (self.sequence_counter + 1) % (2**32)
        return self.sequence_counter

    def start(self):
        # Start the SCGCP Server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            print(f"SGCP Server started on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    print(f"New connection from {address}")

                    # Track client state
                    self.clients[client_socket] = {
                        'address': address,
                        'state': ProtocolState.STATE_CONNECTING,
                        'user_id': None,
                        'username': None,
                        'session_token': None,
                        'capabilities': 0,
                        'groups': set()
                    }

                     # Handle client in a new thread
                    threading.Thread(
                        target=self._handle_client,
                        args=(client_socket,),
                        daemon=True
                    ).start()
                except socket.error as e:
                    if self.running:
                        print(f"Socket error: {e}")

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.cleanup()

    def _handle_client(self, client_socket):
         # Handle all communication with a connected client
        try:
            # Update state to connectingg
            self.clients[client_socket]['state'] = ProtocolState.STATE_CONNECTING
            while self.running and client_socket in self.clients:
                try:
                     # Receive and parse message header
                    header_data = self._recv_exact(client_socket, HEADER_SIZE)
                    if not header_data:
                        break
                    header = struct.unpack('!BBHIIB3s', header_data)
                    payload_length = header[2]

                     # Receive message payload if present
                    payload_data = b''
                    if payload_length > 0:
                        payload_data = self._recv_exact(client_socket, payload_length)
                        if not payload_data:
                            break
                    message_data = header_data + payload_data
                    message = SGCPMessage.deserialize(message_data)

                    # Process the received protocol message
                    self._process_message(client_socket, message)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error handling client {self.clients[client_socket]['address']}: {e}")
                    self._send_error(client_socket, ErrorCode.ERR_INTERNAL_ERROR, str(e))
                    break
        except Exception as e:
            print(f"Client handler error: {e}")
        finally:
            self._cleanup_client(client_socket)

    def _recv_exact(self, sock, length):
        # Receive an exact number of bytes from a socket
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return b''
            data += chunk
        return data

    def _process_message(self, client_socket, message):
        # Dispatches messages to the appropriate handler based on state/type
        client_info = self.clients[client_socket]
        current_state = client_info['state']
        msg_type = MessageType(message.header.message_type)
        print(f"Processing {msg_type.name} in state {current_state.name}")

        if current_state == ProtocolState.STATE_CONNECTING:
            if msg_type == MessageType.MSG_HELLO:
                self._handle_hello(client_socket, message)
            else:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Expected HELLO")

        elif current_state == ProtocolState.STATE_HELLO_SENT:
            if msg_type == MessageType.MSG_CAPABILITIES:
                self._handle_capabilities(client_socket, message)
            else:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Expected CAPABILITIES")

        elif current_state == ProtocolState.STATE_AUTHENTICATING:
            if msg_type == MessageType.MSG_AUTH_REQUEST:
                self._handle_auth_request(client_socket, message)
            else:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Expected AUTH_REQUEST")

        elif current_state == ProtocolState.STATE_ACTIVE:
            self._handle_active_message(client_socket, message)

        else:
            self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, f"Invalid state: {current_state}")

    def _handle_hello(self, client_socket, message):
        # Handles initial HELLO from client (protocol negotiation)
        try:
            #parse hello payload
            payload = message.payload
            if len(payload) < 7: #minimum size
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Invalid HELLO payload")
                return
            major_version = payload[0]
            minor_version = payload[1]
            supported_features = struct.unpack('!I', payload[2:6])[0]
            client_id_length = struct.unpack('!H', payload[6:8])[0]

            if len(payload) < 8 + client_id_length:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Invalid client ID length")
                return
            
            client_id = payload[8:8+client_id_length].decode('utf-8')

            # Check version compability
            if major_version != PROTOCOL_VERSION:
                self._send_error(client_socket, ErrorCode.ERR_VERSION_MISMATCH, "Unsupported version")
                return
            
             # Build and send HELLO response
            hello_response = struct.pack('!BBIH', PROTOCOL_VERSION, 0,
                                       Capabilities.CAP_BASIC_CHAT | Capabilities.CAP_FILE_TRANSFER,
                                       len("SGCP_Server"))
            hello_response += b"SGCP_Server"
            response = SGCPMessage(MessageType.MSG_HELLO, hello_response)
            response.set_sequence_number(self._get_next_sequence())
            self._send_message(client_socket, response)

            #Update client state
            self.clients[client_socket]['state'] = ProtocolState.STATE_HELLO_SENT
            self.clients[client_socket]['client_id'] = client_id

        except Exception as e:
            self._send_error(client_socket, ErrorCode.ERR_INTERNAL_ERROR, str(e))

    def _handle_capabilities(self, client_socket, message):
         # Handles capabilities negotiation with the client (MSG_CAPABILITIES)

        try:
            if len(message.payload) < 4:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Invalid CAPABILITIES payload")
                return
            
            client_capabilities = struct.unpack('!I', message.payload[:4])[0]

            # Store client capabilities
            self.clients[client_socket]['capabilities'] = client_capabilities

            # Send server capabilities 
            server_caps = Capabilities.CAP_BASIC_CHAT | Capabilities.CAP_FILE_TRANSFER
            caps_payload = struct.pack('!I', server_caps)

            response = SGCPMessage(MessageType.MSG_CAPABILITIES, caps_payload)
            response.set_sequence_number(self._get_next_sequence())
            self._send_message(client_socket, response)

            # Move to authentication state
            self.clients[client_socket]['state'] = ProtocolState.STATE_AUTHENTICATING

        except Exception as e:
            self._send_error(client_socket, ErrorCode.ERR_INTERNAL_ERROR, str(e))

    def _handle_auth_request(self, client_socket, message):
        # Handles user authentication requests (MSG_AUTH_REQUEST)
        try:
            payload = message.payload
            if len(payload) < 5:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Invalid AUTH_REQUEST payload")
                return
            
            auth_method = payload[0]
            username_length = struct.unpack('!H', payload[1:3])[0]
            auth_data_length = struct.unpack('!H', payload[3:5])[0]

            if len(payload) < 5 + username_length + auth_data_length:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Invalid auth data length")
                return
            
            username = payload[5:5+username_length].decode('utf-8')
            password = payload[5+username_length:5+username_length+auth_data_length].decode('utf-8')

            # Authenticate user
            if username in self.users and self.users[username]['password'] == self._hash_password(password):
                # Authenticate successful
                session_token = self._generate_session_token()
                user_id = self.users[username]['user_id']

                self.clients[client_socket]['username'] = username
                self.clients[client_socket]['user_id'] = user_id
                self.clients[client_socket]['session_token'] = session_token
                self.clients[client_socket]['state'] = ProtocolState.STATE_AUTHENTICATED

                # Send sucess response
                success_msg = f"Welcome {username}!"
                auth_response = struct.pack('!BHI', 1, len(success_msg), session_token)
                auth_response += success_msg.encode('utf-8')

                response = SGCPMessage(MessageType.MSG_AUTH_RESPONSE, auth_response)
                response.set_sequence_number(self._get_next_sequence())
                self._send_message(client_socket, response)

                # Move to active state
                self.clients[client_socket]['state'] = ProtocolState.STATE_ACTIVE

                print(f"User {username} authenticated successfully")

            else:
                # Authentication failed
                error_msg = "Invalid credentials"
                auth_response = struct.pack('!BHI', 0, len(error_msg), 0)
                auth_response += error_msg.encode('utf-8')

                response = SGCPMessage(MessageType.MSG_AUTH_RESPONSE, auth_response)
                response.set_sequence_number(self._get_next_sequence())
                self._send_message(client_socket, response)

                self.clients[client_socket]['state'] = ProtocolState.STATE_ERROR

        except Exception as e:
            self._send_error(client_socket, ErrorCode.ERR_INTERNAL_ERROR, str(e))

    def _handle_active_message(self, client_socket, message):
        # Handle messages in active state
        msg_type = MessageType(message.header.message_type)

        if msg_type == MessageType.MSG_GROUP_JOIN:
            self._handle_group_join(client_socket, message)
        elif msg_type == MessageType.MSG_GROUP_LEAVE:
            self._handle_group_leave(client_socket, message)
        elif msg_type == MessageType.MSG_GROUP_LIST:
            self._handle_group_list(client_socket, message)
        elif msg_type == MessageType.MSG_CHAT:
            self._handle_chat_message(client_socket, message)
        elif msg_type == MessageType.MSG_KEEPALIVE:
            self._handle_keepalive(client_socket, message)
        elif msg_type == MessageType.MSG_DISCONNECT:
            self._handle_disconnect(client_socket, message)
        else:
            self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, f"Unsupported message type: {msg_type}")

    def _handle_group_join(self, client_socket, message):
        # Handle requests for joining a chat group (MSG_GROUP_JOIN)
        try:
            if len(message.payload) < 4:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Invalid GROUP_JOIN payload")
                return
            
            group_id = struct.unpack('!I', message.payload[:4])[0]
            user_id = self.clients[client_socket]['user_id']

            if group_id not in self.groups:
                self._send_error(client_socket, ErrorCode.ERR_GROUP_NOT_FOUND, "Group not found")
                return
            
            # Add user to group
            self.groups[group_id]['members'].add(user_id)
            self.clients[client_socket]['groups'].add(group_id)

            # Send aCK
            ack_msg = SGCPMessage(MessageType.MSG_ACK)
            ack_msg.set_sequence_number(self._get_next_sequence())
            self._send_message(client_socket, ack_msg)

            print(f"User {self.clients[client_socket]['username']} joined group {group_id}")

        except Exception as e:
            self._send_error(client_socket, ErrorCode.ERR_INTERNAL_ERROR, str(e))

    def _handle_group_leave(self, client_socket, message):
        # Handle request for leaving group chat (MSG_GROUP_LEAVE)
        try:
            if len(message.payload) < 4:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Invalid GROUP_LEAVE payload")
                return
            
            group_id = struct.unpack('!I', message.payload[:4])[0]
            user_id = self.clients[client_socket]['user_id']

            if group_id in self.groups and user_id in self.groups[group_id]['members']:
                self.groups[group_id]['members'].remove(user_id)
                self.clients[client_socket]['groups'].discard(group_id)

                # Send aCK
                ack_msg = SGCPMessage(MessageType.MSG_ACK)
                ack_msg.set_sequence_number(self._get_next_sequence())
                self._send_message(client_socket, ack_msg)

                print(f"User {self.clients[client_socket]['username']} left group {group_id}")
            else:
                self._send_error(client_socket, ErrorCode.ERR_GROUP_NOT_FOUND, "Not in group")

        except Exception as e:
            self._send_error(client_socket, ErrorCode.ERR_INTERNAL_ERROR, str(e))

    def _handle_group_list(self, client_socket, message):
        # Return a list of all public groups to client (MSG_GROUP_LIST)
        try:
            #Build group list
            group_list = []
            for group_id, group_info in self.groups.items():
                if group_info['public']:
                    group_list.append({
                        'id': group_id,
                        'name': group_info['name'],
                        'members': len(group_info['members'])
                    })

                    # Serialize group list as Json
            group_data = json.dumps(group_list).encode('utf-8')

            response = SGCPMessage(MessageType.MSG_GROUP_LIST, group_data)
            response.set_sequence_number(self._get_next_sequence())
            self._send_message(client_socket, response)

        except Exception as e:
            self._send_error(client_socket, ErrorCode.ERR_INTERNAL_ERROR, str(e))

    def _handle_chat_message(self, client_socket, message):
        #Broadcast a chat message to all group members (MSG_CHAT)
        try:
            if len(message.payload) < 12:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Invalid CHAT payload")
                return
            
            group_id = struct.unpack('!I', message.payload[:4])[0]
            sender_id = struct.unpack('!I', message.payload[4:8])[0]
            msg_length = struct.unpack('!H', message.payload[8:10])[0]

            if len(message.payload) < 10 + msg_length:
                self._send_error(client_socket, ErrorCode.ERR_INVALID_MESSAGE, "Invalid message length")
                return
            
            chat_text = message.payload[10:10+msg_length].decode('utf-8')

            # Verify user is in group
            user_id = self.clients[client_socket]['user_id']
            if group_id not in self.groups or user_id not in self.groups[group_id]['members']:
                self._send_error(client_socket, ErrorCode.ERR_PERMISSION_DENIED, "Not in group")
                return
            
            # Boradcast message to all group members
            self._broadcast_to_group(group_id, message, sender_client=client_socket)

            print(f"Chat message from {self.clients[client_socket]['username']} in group {group_id}: {chat_text}")

        except Exception as e:
            self._send_error(client_socket, ErrorCode.ERR_INTERNAL_ERROR, str(e))

    def _handle_keepalive(self, client_socket, message):
        # Respond to keepalive pings from the client (MSG_KEEPALIVE)
        response = SGCPMessage(MessageType.MSG_KEEPALIVE)
        response.set_sequence_number(self._get_next_sequence())
        self._send_message(client_socket, response)

    def _handle_disconnect(self, client_socket, message):
        # Clean up and disconnect a client (MSG_DISCONNECT)
        print(f"User {self.clients[client_socket].get('username', 'unknown')} disconnecting")
        self.clients[client_socket]['state'] = ProtocolState.STATE_DISCONNECTING
        self._cleanup_client(client_socket)

    def _broadcast_to_group(self, group_id, message, sender_client=None):
        # Send a message to all group members except the sender
        if group_id not in self.groups:
            return
        
        group_members = self.groups[group_id]['members']

        for client_socket, client_info in self.clients.items():
            if (client_info['user_id'] in group_members and 
                client_socket != sender_client and
                client_info['state'] == ProtocolState.STATE_ACTIVE):
                try:
                    self._send_message(client_socket, message)
                except:
                    # Client disconnected, clean up
                    self._cleanup_client(client_socket)

    def _send_message(self, client_socket, message):
        # Serialize and send a message to a client
        try:
            data = message.serialize()
            client_socket.send(data)
        except Exception as e:
            print(f"Error sending message: {e}")
            raise

    def _send_error(self, client_socket, error_code, error_msg):
         # Send an error message to a client
        try:
            error_payload = struct.pack('!BH', error_code, len(error_msg))
            error_payload += error_msg.encode('utf-8')

            error_message = SGCPMessage(MessageType.MSG_ERROR, error_payload, MessageFlags.FLAG_URGENT)
            error_message.set_sequence_number(self._get_next_sequence())
            self._send_message(client_socket, error_message)

        except Exception as e:
            print(f"Error sending error message: {e}")

    def _cleanup_client(self, client_socket):
          # Remove a client from server and all groups
        try:
            if client_socket in self.clients:
                client_info = self.clients[client_socket]

                # Remove from groups
                user_id = client_info.get('user_id')
                if user_id:
                    for group_id in list(client_info.get('groups', set())):
                        if group_id in self.groups and user_id in self.groups[group_id]['members']:
                            self.groups[group_id]['members'].remove(user_id)

                # Remove client
                del self.clients[client_socket]
                print(f"Cleaned up client {client_info.get('username', 'unknown')}")

            client_socket.close()

        except Exception as e:
            print(f"Error cleaning up client: {e}")

    def cleanup(self):
        # Shutdown the server and disconnect all clients
        self.running = False
        if self.socket:
            self.socket.close()
        
        # Close all client connections
        for client_socket in list(self.clients.keys()):
            self._cleanup_client(client_socket)

def run_server():
    # Parse command-line arguments and launch server
    parser = argparse.ArgumentParser(description='SGCP Server')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help=f'Server port (default: {DEFAULT_PORT})')
    args = parser.parse_args()

     # Create and start the server
    server = SGCPServer(args.host, args.port)
    try:
        server.start()
    # # shut down the server on Ctrl+C.
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.cleanup()

if __name__ == "__main__":
    run_server()
