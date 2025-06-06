# client.py

import socket
import threading
import struct
import time
import json
import argparse
import sys

# Import protocol definitions and messages classes
from sgcp_protocol import (
    PROTOCOL_VERSION, HEADER_SIZE, DEFAULT_PORT,
    MessageType, MessageFlags, ErrorCode, ProtocolState, Capabilities,
    SGCPMessage
)

class SGCPClient:
    # SGCP Client Implementation

    def __init__(self, server_host='localhost', server_port=DEFAULT_PORT):
        # Initialize client state and connection info
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.state = ProtocolState.STATE_DISCONNECTED
        self.sequence_counter = 0
        self.session_token = None
        self.user_id = None
        self.username = None
        self.running = False
        self.current_groups = set()

    def _get_next_sequence(self):
        # Generate the next message sequence number (wraps around at 2^32)
        self.sequence_counter = (self.sequence_counter + 1) % (2**32)
        return self.sequence_counter

    def connect(self):
        try:
            # Connect to the SGCP server (TCP)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            self.state = ProtocolState.STATE_CONNECTING

            print(f"Connected to SGCP server at {self.server_host}:{self.server_port}")

            # Start a background thread to receive messages from server
            self.running = True
            threading.Thread(target=self._message_receiver, daemon=True).start()
            return True
        
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def _message_receiver(self):
        # Continuously receive and handle messages from the server
        while self.running:
            try:
                # Receive header
                header_data = self._recv_exact(HEADER_SIZE)
                if not header_data:
                    break

                # Parse header
                header = struct.unpack('!BBHIIB3s', header_data)
                payload_length = header[2]

                # Receive payload
                payload_data = b''
                if payload_length > 0:
                    payload_data = self._recv_exact(payload_length)
                    if not payload_data:
                        break

                # Deserialize message 
                message_data = header_data + payload_data
                message = SGCPMessage.deserialize(message_data)

                # Process received message
                self._process_received_message(message)

            except socket.timeout:
                continue
            except Exception as e:
                print(f"Message receiver error: {e}")
                break

    def _recv_exact(self, length):

        # Receive an exact number of bytes from the socket
        data = b''
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                return b''
            data += chunk
        return data

    def _process_received_message(self, message):
        # Route the received message to the appropriate handler
        msg_type = MessageType(message.header.message_type)

        if msg_type == MessageType.MSG_HELLO:
            self._handle_server_hello(message)
        elif msg_type == MessageType.MSG_CAPABILITIES:
            self._handle_server_capabilities(message)
        elif msg_type == MessageType.MSG_AUTH_RESPONSE:
            self._handle_auth_response(message)
        elif msg_type == MessageType.MSG_GROUP_LIST:
            self._handle_group_list_response(message)
        elif msg_type == MessageType.MSG_CHAT:
            self._handle_chat_message(message)
        elif msg_type == MessageType.MSG_ACK:
            self._handle_ack(message)
        elif msg_type == MessageType.MSG_ERROR:
            self._handle_error(message)
        elif msg_type == MessageType.MSG_KEEPALIVE:
            # Keepalive response, no action needed
            pass # Ignore keepalive responses for now
        else:
            print(f"Received unhandled message type: {msg_type}")

    def _handle_server_hello(self, message):
        # Handle server's HELLO (version/capability negotiation)
        try:
            payload = message.payload
            if len(payload) < 7:
                print("Invalid HELLO response")
                return
            
            version = payload[0]
            minor = payload[1]
            server_features = struct.unpack('!I', payload[2:6])[0]
            server_id_len = struct.unpack('!H', payload[6:8])[0]
            server_id = payload[8:8+server_id_len].decode('utf-8')

            print(f"Server: {server_id}, Version: {version}.{minor}")

            # Send capabilities to server
            caps_payload = struct.pack('!I', Capabilities.CAP_BASIC_CHAT | Capabilities.CAP_FILE_TRANSFER)
            caps_msg = SGCPMessage(MessageType.MSG_CAPABILITIES, caps_payload)
            caps_msg.set_sequence_number(self._get_next_sequence())
            self._send_message(caps_msg)

            self.state = ProtocolState.STATE_CAPABILITY_NEGO

        except Exception as e:
            print(f"Error handling HELLO: {e}")

    def _handle_server_capabilities(self, message):
        # Handle server's capability response, prompt for authentication
        try:
            if len(message.payload) >= 4:
                server_caps = struct.unpack('!I', message.payload[:4])[0]
                print(f"Server capabilities: 0x{server_caps:08x}")

            self.state = ProtocolState.STATE_AUTHENTICATING
            print("Ready for authentication. Use 'login <username> <password>' command.")

        except Exception as e:
            print(f"Error handling capabilities: {e}")

    def _handle_auth_response(self, message):
        # Handle authentication response (success/failure)
        try:
            payload = message.payload
            if len(payload) < 7:
                print("Invalid AUTH_RESPONSE")
                return
            
            status = payload[0]
            msg_length = struct.unpack('!H', payload[1:3])[0]
            session_token = struct.unpack('!I', payload[3:7])[0]

            auth_message = payload[7:7+msg_length].decode('utf-8')

            if status == 1: # Success
                self.session_token = session_token
                self.state = ProtocolState.STATE_ACTIVE
                print(f"Authentication successful: {auth_message}")
                print("Available commands: join <group_id>, leave <group_id>, list, chat <message>, quit")
            else: #Failure
                print(f"Authentication failed: {auth_message}")
                self.state = ProtocolState.STATE_ERROR

        except Exception as e:
            print(f"Error handling auth response: {e}")

    def _handle_group_list_response(self, message):
        # Display list of available groups to user
        try:
            group_data = json.loads(message.payload.decode('utf-8'))
            print("\nAvailable groups:")
            for group in group_data:
                print(f"  {group['id']}: {group['name']} ({group['members']} members)")
            print()

        except Exception as e:
            print(f"Error handling group list: {e}")

    def _handle_chat_message(self, message):
        # Display a chat message received from a group
        try:
            payload = message.payload
            if len(payload) < 10:
                return
            
            group_id = struct.unpack('!I', payload[:4])[0]
            sender_id = struct.unpack('!I', payload[4:8])[0]
            msg_length = struct.unpack('!H', payload[8:10])[0]

            if len(payload) >= 10 + msg_length:
                chat_text = payload[10:10+msg_length].decode('utf-8')
                print(f"[Group {group_id}] User {sender_id}: {chat_text}")

        except Exception as e:
            print(f"Error handling chat message: {e}")

    def _handle_ack(self, message):
        # Inform user that a command was acknowledged by the server
        print("Command acknowledged by server")

    def _handle_error(self, message):
        # Display error messages from server
        try:
            if len(message.payload) >= 3:
                error_code = message.payload[0]
                msg_length = struct.unpack('!H', message.payload[1:3])[0]
                error_msg = message.payload[3:3+msg_length].decode('utf-8')
                print(f"Server error ({error_code}): {error_msg}")
        except Exception as e:
            print(f"Error handling error message: {e}")

    def _send_message(self, message):
        # Serialize and send a message to the server
        try:
            data = message.serialize()
            self.socket.send(data)
        except Exception as e:
            print(f"Error sending message: {e}")

    def handshake(self):
        # Start the initial protocol handshake (send HELLO)
        try:
            #Send HELLO message
            client_id = "SGCP_Client_v1.0"
            hello_payload = struct.pack('!BBIH', PROTOCOL_VERSION, 0,
                                      Capabilities.CAP_BASIC_CHAT | Capabilities.CAP_FILE_TRANSFER,
                                      len(client_id))
            hello_payload += client_id.encode('utf-8')

            hello_msg = SGCPMessage(MessageType.MSG_HELLO, hello_payload, MessageFlags.FLAG_ENCRYPTED)
            hello_msg.set_sequence_number(self._get_next_sequence())
            self._send_message(hello_msg)

            self.state = ProtocolState.STATE_HELLO_SENT
            print("Handshake initiated...")

            return True
        
        except Exception as e:
            print(f"Handshake failed: {e}")
            return False

    def login(self, username, password):
        # Authenticate with the server using provided credentials
        if self.state != ProtocolState.STATE_AUTHENTICATING:
            print("Not ready for authentication")
            return False
        
        try:
            # Send authentication request
            auth_payload = struct.pack('!BHH', 0, len(username), len(password))
            auth_payload += username.encode('utf-8')
            auth_payload += password.encode('utf-8')

            auth_msg = SGCPMessage(MessageType.MSG_AUTH_REQUEST, auth_payload,
                                 MessageFlags.FLAG_ENCRYPTED | MessageFlags.FLAG_REQUIRES_ACK)
            auth_msg.set_sequence_number(self._get_next_sequence())
            self._send_message(auth_msg)

            self.username = username
            print(f"Authenticating as {username}...")

            return True
        
        except Exception as e:
            print(f"Login failed: {e}")
            return False

    def join_group(self, group_id):
        # Send a join group request to the server
        if self.state != ProtocolState.STATE_ACTIVE:
            print("Not authenticated")
            return False
        
        try:
            join_payload = struct.pack('!I', group_id)
            join_msg = SGCPMessage(MessageType.MSG_GROUP_JOIN, join_payload,
                                 MessageFlags.FLAG_ENCRYPTED | MessageFlags.FLAG_REQUIRES_ACK)
            join_msg.set_sequence_number(self._get_next_sequence())
            self._send_message(join_msg)

            self.current_groups.add(group_id)
            print(f"Joining group {group_id}...")

            return True
        
        except Exception as e:
            print(f"Failed to join group: {e}")
            return False

    def leave_group(self, group_id):
        # Send a leave group request to the server
        if self.state != ProtocolState.STATE_ACTIVE:
            print("Not authenticated")
            return False
        
        try:
            leave_payload = struct.pack('!I', group_id)
            leave_msg = SGCPMessage(MessageType.MSG_GROUP_LEAVE, leave_payload,
                                  MessageFlags.FLAG_ENCRYPTED | MessageFlags.FLAG_REQUIRES_ACK)
            leave_msg.set_sequence_number(self._get_next_sequence())
            self._send_message(leave_msg)

            self.current_groups.discard(group_id)
            print(f"Leaving group {group_id}...")

            return True
        
        except Exception as e:
            print(f"Failed to leave group: {e}")
            return False

    def list_groups(self):
        # Request the list of public groups from server
        if self.state != ProtocolState.STATE_ACTIVE:
            print("Not authenticated")
            return False
        
        try:
            list_msg = SGCPMessage(MessageType.MSG_GROUP_LIST, b'', MessageFlags.FLAG_ENCRYPTED)
            list_msg.set_sequence_number(self._get_next_sequence())
            self._send_message(list_msg)

            return True
        
        except Exception as e:
            print(f"Failed to request group list: {e}")
            return False

    def send_chat_message(self, group_id, message):
        # Send a chat message to a specific group
        if self.state != ProtocolState.STATE_ACTIVE:
            print("Not authenticated")
            return False
        
        if group_id not in self.current_groups:
            print(f"Not a member of group {group_id}")
            return False
        
        try:
            message_bytes = message.encode('utf-8')
            chat_payload = struct.pack('!IIH', group_id, self.user_id or 0, len(message_bytes))
            chat_payload += message_bytes

            chat_msg = SGCPMessage(MessageType.MSG_CHAT, chat_payload, MessageFlags.FLAG_ENCRYPTED)
            chat_msg.set_sequence_number(self._get_next_sequence())
            self._send_message(chat_msg)

            return True
        
        except Exception as e:
            print(f"Failed to send message: {e}")
            return False

    def send_keepalive(self):
        # Send a keepalive (heartbeat) message to the server
        try:
            keepalive_msg = SGCPMessage(MessageType.MSG_KEEPALIVE)
            keepalive_msg.set_sequence_number(self._get_next_sequence())
            self._send_message(keepalive_msg)
        except Exception as e:
            print(f"Failed to send keepalive: {e}")

    def disconnect(self):
        # Disconnect from server
        try:
            if self.socket and self.state != ProtocolState.STATE_DISCONNECTED:
                disconnect_msg = SGCPMessage(MessageType.MSG_DISCONNECT)
                disconnect_msg.set_sequence_number(self._get_next_sequence())
                self._send_message(disconnect_msg)

                self.state = ProtocolState.STATE_DISCONNECTING

        except:
            pass
        finally:
            self.cleanup()

    def cleanup(self):
        # Final resource cleanup (close socket, update state)
        self.running = False
        self.state = ProtocolState.STATE_DISCONNECTED
        if self.socket:
            self.socket.close()
            self.socket = None

def run_client():
    # Parse command-line arguments for server host/port
    parser = argparse.ArgumentParser(description='SGCP Client')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help=f'Server port (default: {DEFAULT_PORT})')
    args = parser.parse_args()
    client = SGCPClient(args.host, args.port)
    try:
        # Connect to the server and perform protocol handshake
        if not client.connect():
            return
        if not client.handshake():
            return
        time.sleep(1)

        # Show help/usage to user
        print("\nSGCP Client Ready")
        print("Commands:")
        print("  login <username> <password> - Authenticate with server")
        print("  list - List available groups")
        print("  join <group_id> - Join a group")
        print("  leave <group_id> - Leave a group")
        print("  chat <group_id> <message> - Send message to group")
        print("  quit - Disconnect and exit")
        print()

        # Main loop: process user command
        while client.running and client.state != ProtocolState.STATE_DISCONNECTED:
            try:
                command = input("> ").strip().split()
                if not command:
                    continue
                cmd = command[0].lower()
                if cmd == 'quit':
                    break
                elif cmd == 'login' and len(command) >= 3:
                    client.login(command[1], command[2])
                elif cmd == 'list':
                    client.list_groups()
                elif cmd == 'join' and len(command) >= 2:
                    try:
                        group_id = int(command[1])
                        client.join_group(group_id)
                    except ValueError:
                        print("Invalid group ID")
                elif cmd == 'leave' and len(command) >= 2:
                    try:
                        group_id = int(command[1])
                        client.leave_group(group_id)
                    except ValueError:
                        print("Invalid group ID")
                elif cmd == 'chat' and len(command) >= 3:
                    try:
                        group_id = int(command[1])
                        message = ' '.join(command[2:])
                        client.send_chat_message(group_id, message)
                    except ValueError:
                        print("Invalid group ID")
                else:
                    print("Invalid command or insufficient arguments")
            except KeyboardInterrupt:
                break
            except EOFError:
                break
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        print("Disconnecting...")
        client.disconnect()

# Run client if this script is executed directly 
if __name__ == "__main__":
    run_client()
