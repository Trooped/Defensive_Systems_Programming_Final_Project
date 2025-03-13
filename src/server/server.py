"""
File: server.py
Author: Omri Peretz
Date: March 2025
Assignment: Maman 15
Course: Defensive Systems Programming

Description:
This file is a server program written in Python, that manages text transfers between different clients.
The client and server communicate over TCP, with a compatible, agreed upon protocol.
The data is being sent in little endian format.
The text & files being sent are encrypted and decrypted using a 16 byte symmetric key (AES - CBC).
The symmetric key is encrypted and sent using RSA.
The symmetric key transferred between clients in the following mechanism:
0. Client A and Client B register to the server, and create a private and public key.
1. Client A send a request for the public key of client B
2. Client A send client B a request for a symmetric key,
(** if client A doesn't send this request, client B CAN'T send client A a symmetric key).
3. Client B receives the request
4. Client B sends a request for the public key of client A
5. Client B Creates a symmetric key, encrypts it using client A's public key, and requests to send it to client A
6. Client A receives the symmetric key, decrypts it using his private key
7. Client A and Client B can communicate freely, with encrypted texts and files using their shared symmetric key

The client can send the following requests to the server (number in parentheses = client input code):
- 600: Registration request (110)
- 601: Client list request (120)
- 602: Public key of other client request (130)
- 603: Send message request (no specific input)
- 603 - 1: Receive symmetric key from other client request (151)
- 603 - 2: Send symmetric key to other client request (152)
- 603 - 3: Text message send request (150)
- 603 - 4: File send request (153)
- 604: waiting messages addressed to the client request (140)

The server will do the operation and respond with the following status codes:
- 2100: Success: Registration suceeded
- 2101: Success: List of clients sent
- 2102: Success: Public key of other client sent to requesting client
- 2103: Success: Message sent to client (held at server database until client requests to read it)
- 2104: Success: List of waiting messages sent to client
- 9000: Error: General server error
"""

# import statements
import socket
import selectors
import struct
import uuid
from datetime import datetime
from enum import Enum
import sqlite3
from typing import Any, Literal

import select

# general constants:
VERSION_NUMBER = 2
SOCKET_CHUNK_SIZE = 1024


class MessageType(Enum):
    """
    Message Type Codes.
    """
    SYMMETRICAL_KEY_REQUEST = 1  # Message content is empty and Content Size = 0
    SYMMETRICAL_KEY_SEND = 2  # Message content has a symmetrical key, encrypted by the public key of the target client
    SEND_TEXT_MESSAGE = 3  # Message content contains text encrypted by the symmetric key
    SEND_FILE_MESSAGE = 4  # Message content contains file content encrypted by the symmetric key


class MessageOffset(Enum):
    """
    Each message contains:
    - Destination Client ID
    - Message Type
    - Content size (message size)
    - Message content (if applicable)
    """
    MIN_MESSAGE_SIZE = 21
    TO_CLIENT_ID_MESSAGE_SIZE = 16
    MESSAGE_TYPE_SIZE = 1
    MESSAGE_CONTENT_SIZE = 4


class RequestOffset(Enum):
    """
    Each request contains:
    - Client ID
    - Version
    - Request Code
    - Payload Size
    - payload
    """
    CLIENT_ID_SIZE = 16
    CLIENT_VERSION_SIZE = 1
    REQUEST_CODE_SIZE = 2
    REQUEST_PAYLOAD_SIZE = 4
    MIN_REQUEST_SIZE = 23


class RequestFieldsSizes(Enum):
    """
    Request fields sizes.
    """
    CLIENT_NAME_SIZE = 255
    PUBLIC_KEY_SIZE = 160
    CLIENT_ID_SIZE = 16
    MESSAGE_TYPE_SIZE = 1
    CONTENT_SIZE_SIZE = 4


class ResponseFieldsSizes(Enum):
    """
    Response Fields Sizes.
    """
    VERSION_SIZE = 1
    RESPONSE_CODE_SIZE = 2
    PAYLOAD_SIZE = 4
    PUBLIC_KEY_SIZE = 160
    CLIENT_ID_SIZE = 16
    CLIENT_NAME_SIZE = 255
    MESSAGE_ID_SIZE = 4
    MESSAGE_TYPE_SIZE = 1
    MESSAGE_CONTENT_SIZE = 4


class EncryptionKeysSizes(Enum):
    """
    Encryption Keys sizes.
    """
    SYMMETRIC_KEY_SIZE = 16  # bytes
    PRIVATE_KEY_SIZE = 128  # bytes
    PUBLIC_KEY_SIZE = 160  # bytes


class RequestType(Enum):
    """
    Here we define the different request types.
    The payload field differs from request to request, and it's dictated by the request type.
    In each comment the payload field will be described here.
    """
    REGISTER_REQUEST = 600  # Client name (up to 255 bytes ASCII null terminated string) + \
    # Public key (160 bytes public key).
    CLIENT_LIST_REQUEST = 601  # Payload field is empty, and payload size = 0.
    PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST = 602  # Client ID (16 bytes) of the target client.
    SEND_MESSAGE_REQUEST = 603  # Message request structure (as part of payload) is described in MessageType class.
    RECEIVE_INCOMING_MESSAGES_REQUEST = 604  # Payload field is empty and payload size = 0.


class ResponseType(Enum):
    """
    Here we define the different response types' numbers.
    """
    CLIENT_REGISTER_RESPONSE_SUCCESS = 2100  # Payload will be the Client ID
    CLIENT_LIST_RESPONSE_SUCCESS = 2101  # Payload will contain the Client ID,
    # followed by all client names but the requesting Client.
    PUBLIC_KEY_OF_OTHER_CLIENT_RESPONSE_SUCCESS = 2102  # client ID + public key
    SEND_MESSAGE_RESPONSE_SUCCESS = 2103  # Client ID + Message ID
    RECEIVE_INCOMING_MESSAGES_RESPONSE_SUCCESS = 2104  # Client ID + Message ID + Message Type
    # + Message Size + Message content (ONE MESSAGE AFTER THE OTHER)
    GENERAL_ERROR_RESPONSE = 9000  # Payload field is empty, Payload size = 0


class Server:
    """
    A modular server class that handles multiple client connections using selectors.
    Includes:
    - Non-blocking socket handling
    - Client request and server response handled by ClientManager class
    """
    # port number constants:
    MIN_PORT_NUMBER = 0
    MAX_PORT_NUMBER = 65535
    DEFAULT_PORT_NUMBER = 1357
    PORT_FILE_NAME = "myport.info"
    MAX_CONNECTIONS = 100

    IP_ADDRESS = '127.0.0.1'

    def __init__(self):
        self.host = self.IP_ADDRESS
        self.port = self.read_port()
        self.sel = selectors.DefaultSelector()
        self.running = True
        self.db = Database()
        self.sock = None
        self.clients = {}

    def read_port(self) -> int:
        """Reads the server port from a configuration file."""
        try:
            with open(self.PORT_FILE_NAME, mode="r", encoding="utf-8") as port_file:
                port_data = port_file.read().strip()
                try:
                    port = int(port_data)
                    if self.MIN_PORT_NUMBER <= port <= self.MAX_PORT_NUMBER:
                        return port
                    else:
                        print(
                            f"WARNING: Port number in '{self.PORT_FILE_NAME}' is out of valid range \
                            ({self.MIN_PORT_NUMBER}-{self.MAX_PORT_NUMBER}): {port}")
                except ValueError:
                    print(f"WARNING: Port number in '{self.PORT_FILE_NAME}' is not a valid integer: {port_data}")
        except FileNotFoundError:
            print(f"WARNING: Port file '{self.PORT_FILE_NAME}' not found.")
        except Exception as e:
            print(f"WARNING: Failed to read port file '{self.PORT_FILE_NAME}': {e}")

        # Fallback to the default port
        print(f"Returning default port number: {self.DEFAULT_PORT_NUMBER}")
        return self.DEFAULT_PORT_NUMBER

    def _create_socket(self) -> None:
        """Creates the main server socket and registers it with the selector."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(self.MAX_CONNECTIONS)
        self.sock.setblocking(False)
        self.sel.register(self.sock, selectors.EVENT_READ, self._accept_client)
        print(f"MessageU server is running on {self.host}:{self.port}")
        print(f"Waiting for connections...")

    def _accept_client(self, sock: socket.socket, mask) -> None:
        """Handles new client connections."""
        try:
            conn, addr = sock.accept()
            conn.setblocking(False)
            print("-----------------------------")
            print(f"New connection from {addr}")
            print()

            # Create a ClientManager for this connection
            client = ClientManager(conn, self.db, self.sel)
            self.clients[conn.fileno()] = client  # Store client reference

            # Register the client socket with the selector for reading
            self.sel.register(conn, selectors.EVENT_READ, self._read_client)
        except Exception as e:
            print(f"ERROR: Failed to accept a client: {e}")

    def _read_client(self, sock: socket.socket, mask) -> None:
        """Called when a client socket is ready to read data."""
        client = self.clients.get(sock.fileno())

        if client:
            try:
                success = client.handle_client(sock, mask)
                if not success:
                    print(f"Client {sock.fileno()} disconnected.\n")
                    self._remove_client(sock)
                else:
                    print(f"Closing connection after response for client {sock.fileno()}")
                    self._remove_client(sock)  # Always close after one response
            except (ConnectionResetError, BrokenPipeError):
                print(f"Client {sock.fileno()} crashed or lost connection.")
                self._remove_client(sock)
        else:
            print(f"WARNING: No client associated with socket {sock.fileno()}")
            self._remove_client(sock)

    def _remove_client(self, sock: socket.socket):
        """Unregisters and closes a client socket properly."""
        try:
            self.sel.unregister(sock)  # Remove from selector
            sock.close()  # Close the connection
            self.clients.pop(sock.fileno(), None)  # Remove from dictionary
        except Exception as e:
            print(f"WARNING: Failed to clean up client socket {sock.fileno()}: {e}")

    def run(self) -> None:
        """Runs the server and processes events using the selector."""
        self._create_socket()
        try:
            while self.running:
                events = self.sel.select(timeout=None)  # Wait for events

                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)  # Call the registered function (_read_client)
        except KeyboardInterrupt:
            print("\nServer shutting down (Ctrl+C detected).")
        except Exception as e:
            print(f"ERROR: Unexpected error in server loop: {e}")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stops the server, closing all connections and the main socket."""
        print("Stopping the server...")
        self.running = False

        # Close all client connections
        for fileno, client in list(self.clients.items()):
            print(f"Closing client {fileno}...")
            client.socket.close()
            self.sel.unregister(client.socket)

        self.clients.clear()  # Clear client dictionary

        # Unregister and close the main server socket safely
        if self.sock:
            try:
                self.sel.unregister(self.sock)
            except KeyError:
                pass  # Socket might already be unregistered

            self.sock.close()

        self.sel.close()
        print("Server shut down successfully.")


class ClientManager:
    """
    ClientManager class, used to manage client request and response
    """

    def __init__(self, conn, db, sel):
        self.socket = conn
        self.sel = sel
        self.request = None
        self.db = db
        self.client_id = None
        self.username = None
        self.target_client_id = None
        self.message_id = None

    def receive_exact_bytes(self, num_bytes):
        """Utility function that reads exactly num_bytes from the socket, making sure all data is received"""
        received_data = b""
        while len(received_data) < num_bytes:
            chunk = self.socket.recv(num_bytes - len(received_data))
            if not chunk:
                raise ValueError("Socket connection broken while receiving data")
            received_data += chunk
        return received_data

    def process_message_request(self):
        """
        Handles a SEND_MESSAGE_REQUEST (case 603), including message header and content.
        """
        try:
            # Receive basic message header (minimum message size)
            message_header_bytes = self.receive_exact_bytes(MessageOffset.MIN_MESSAGE_SIZE.value)
            self.request.message = Message(message_header_bytes)

            # Receive full message content
            message_content_bytes = self.receive_exact_bytes(self.request.message.content_size)
            self.request.message.parse_message_content(message_content_bytes)

        except ValueError as e:
            raise ValueError(f"Error parsing message from client: {e}")

    def receive_and_process_request(self):
        """
        Receive data from the socket and process it into a Request object.
        """
        try:
            request_bytes = self.receive_exact_bytes(RequestOffset.MIN_REQUEST_SIZE.value)
            if not request_bytes:
                raise ValueError("Request is empty")

            self.request = Request(request_bytes)

            # Checks if the user is registered before making ANY other request.
            if self.request.request_code != RequestType.REGISTER_REQUEST.value:
                username = self.db.get_username_by_uuid(self.request.client_id)
                if username is None or not self.db.does_client_exist(username):
                    raise ValueError("Unregistered user attempts to make a request, cancelling request processing.")

            if self.request.request_code == RequestType.SEND_MESSAGE_REQUEST.value:
                self.process_message_request()
                return

            payload_size = self.request.payload_size
            if payload_size > 0:
                payload_bytes = self.receive_exact_bytes(payload_size)
                self.request.request_bytes = request_bytes + payload_bytes
                self.request.parse_payload()

        except Exception as e:
            raise ValueError(f"Request parsing error: {e}")

    def _print_request_type_message(self):
        request_code = self.request.request_code

        if request_code == RequestType.REGISTER_REQUEST.value:
            print(f"Handling client request to register with the name '{self.request.client_name}'")
        elif self.request.request_code != RequestType.REGISTER_REQUEST.value:
            client_name = self.db.get_username_by_uuid(self.request.client_id)
            if request_code == RequestType.SEND_MESSAGE_REQUEST.value:
                print(
                    f"Handling client request from '{client_name}' to send a message to client "
                    f"'{self.db.get_username_by_uuid(self.request.message.target_client_id)}'")
            elif request_code == RequestType.CLIENT_LIST_REQUEST.value:
                print(f"Handling client request from '{client_name}' to fetch list of all registered clients")
            elif request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:
                print(
                    f"Handling client request from '{client_name}' to fetch public key of client \
                    '{self.db.get_username_by_uuid(self.request.target_client_id)}'.")
            elif request_code == RequestType.RECEIVE_INCOMING_MESSAGES_REQUEST.value:
                print(f"Handling client request from '{client_name} to fetch all incoming messages from the database")
            else:
                raise ValueError(f"Unknown request code: {request_code}")

    def process_request(self):
        """
        Receives the incoming request and processes it.
        """
        print("--- Processing Client Request ---")
        print("Receiving and processing request from the client...")
        self.receive_and_process_request()
        self._print_request_type_message()  # Printing the correct request type

        request_code = self.request.request_code
        if request_code in [RequestType.CLIENT_LIST_REQUEST.value, RequestType.RECEIVE_INCOMING_MESSAGES_REQUEST.value,
                            RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value]:
            return  # There is no request handling logic for the above requests -
            # only data gathering, which will be done in the generate_response
        elif request_code == RequestType.REGISTER_REQUEST.value:
            self.handle_register_request()
        elif request_code == RequestType.SEND_MESSAGE_REQUEST.value:
            self.handle_send_message_request()
        else:
            raise ValueError(f"Unknown request code: {request_code}")

    def handle_client(self, sock, mask):
        """
        Receive the request, process it, generate the response.
        """
        try:
            self.process_request()  # Receiving and processing a request from the client.
            # If it's not a register request, update the client ID to the one received in the request.
            if self.request.request_code != RequestType.REGISTER_REQUEST.value:
                self.client_id = self.request.client_id
            print()
            print("--- Generating Server Response ---")
            self.generate_response()  # Generating and sending a response to the client.
            print()
            # If the client's interaction with the server is successful, update the "last seen" field in the DB.
            if self.request.request_code != RequestType.REGISTER_REQUEST.value:
                self.db.update_last_seen(self.client_id)
            else:
                self.db.update_last_seen(self.client_id.bytes)
        except Exception as e:
            print(f"Error while handling client: {e}")
            Response(self.socket).error_response()

    def generate_response(self):
        """
        Creates a response based on the request result.
        """
        try:
            response = Response(self.socket)

            if self.request.request_code == RequestType.REGISTER_REQUEST.value:
                response.register_response(self.client_id)
            elif self.request.request_code != RequestType.REGISTER_REQUEST.value:
                client_name = self.db.get_username_by_uuid(self.request.client_id)
                if self.request.request_code == RequestType.CLIENT_LIST_REQUEST.value:
                    clients_list = self.db.fetch_all_registered_clients(client_name)
                    print(f"Responding with clients list to client '{client_name}'.")
                    response.client_list_response(clients_list)
                elif self.request.request_code == RequestType.RECEIVE_INCOMING_MESSAGES_REQUEST.value:
                    messages_list = self.db.fetch_messages_to_client(self.request.client_id)
                    print(f"Responding with messages destined to client '{client_name}'.")
                    sent = response.fetching_messages_response(messages_list)
                    if sent:
                        self.db.delete_messages_to_client(self.request.client_id)
                elif self.request.request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:
                    public_key_other_client = self.db.get_public_key_by_id(self.request.target_client_id)
                    print(f"Responding with public key of client \
                    '{self.db.get_username_by_uuid(self.request.target_client_id)}' to client '{client_name}'.")
                    response.public_key_response(self.request.target_client_id, public_key_other_client)
                elif self.request.request_code == RequestType.SEND_MESSAGE_REQUEST.value:
                    print(f"Responding with 'message sent successfully' code")
                    response.message_sent_response(self.target_client_id, self.message_id)
                else:
                    raise ValueError(f"Unknown request code: {self.request.request_code}")
        except Exception as e:
            raise ValueError(f"Response generating error: {e}")

    def handle_register_request(self):
        """
        Handles the register request logic - inserts the new client to the DB and creates a client ID.
        """
        if not self.db.does_client_exist(self.username):
            self.client_id = self.db.insert_client(self.request.client_name, self.request.public_key)
        else:
            raise ValueError(f"Username '{self.username}' already exists in the DB.")

    def handle_send_message_request(self):
        """
        Handles the send message request logic - inserts the message to the DB.
        """
        try:
            from_client_id = self.request.client_id
            self.target_client_id = self.request.message.target_client_id
            message_type = self.request.message.message_type
            message_content = self.request.message.message_content

            self.message_id = self.db.insert_message(self.target_client_id, from_client_id, message_type,
                                                     message_content)
        except Exception as e:
            raise ValueError(f"Error while handling send message request: {e}")


class Request:
    """
    Request class - responsible for parsing the request bytes from the client,
    And then building the request object, with all the relevant fields.
    """
    def __init__(self, request_bytes):
        self.request_bytes = request_bytes
        self.client_id = None
        self.client_version = None
        self.request_code = None
        self.offset = 0
        self.payload_size = None

        self.parse_request_header()  # Initializing all of the above fields.

        """different payload fields, depending on the request (601 and 604 are empty):"""
        if self.request_code == RequestType.REGISTER_REQUEST.value:  # case 600
            self.client_name = None
            self.public_key = None
        elif self.request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:  # case 602
            self.target_client_id = None
        elif self.request_code == RequestType.SEND_MESSAGE_REQUEST.value:  # case 603
            self.message = None

    def parse_request_header(self):
        """
        Parses the request header that came from the client request.
        """
        try:
            min_size = RequestOffset.MIN_REQUEST_SIZE.value
            # The minimum size of a request is 23 bytes (client id + version + code + payload size)
            if len(self.request_bytes) < min_size:
                raise ValueError(
                    f"Request too short. Expected at least {min_size} bytes, got {len(self.request_bytes)}.")

            # Gather all the relevant fields of a basic request
            self.client_id = self._extract_bytes(RequestOffset.CLIENT_ID_SIZE.value, "Client ID")
            self.client_version = self._extract_int(RequestOffset.CLIENT_VERSION_SIZE.value, "<B", "Client Version")
            validate_range("Client version", self.client_version, "uint8_t")
            self.request_code = self._extract_int(RequestOffset.REQUEST_CODE_SIZE.value, "<H", "Request Code")
            validate_range("Request code", self.request_code, "uint16_t")
            self.payload_size = self._extract_int(RequestOffset.REQUEST_PAYLOAD_SIZE.value, "<I", "Payload Size")
            validate_range("Payload size", self.payload_size, "uint32_t")

            return

        except struct.error as e:
            raise ValueError(f"Error unpacking request header -> {e}")
        except Exception as e:
            raise ValueError(f"Invalid request header -> {e}")

    def _extract_int(self, size, fmt, field_name):
        """
        Utility method that extracts an integer (of given size & format) from the request bytes and updates the offset.
        """
        if len(self.request_bytes) < self.offset + size:
            raise ValueError(f"Request too short. No valid {field_name} field received.")

        extracted_value = struct.unpack(fmt, self.request_bytes[self.offset:self.offset + size])[0]

        self.offset += size
        return extracted_value

    def _extract_client_name(self, size):
        """
        Utility function that extracts the client name from the request bytes, removing the null padding.
        """
        if len(self.request_bytes) < self.offset + size:
            raise ValueError("Request is too short, no valid client name was received")

        name_bytes = struct.unpack("<255s", self.request_bytes[self.offset:self.offset + size])
        self.offset += size
        name = name_bytes[0]
        name = name.split(b'\x00', 1)[0]
        name = name.decode("ascii")
        return name

    def _extract_bytes(self, size, field_name):
        """
        Extracts a fixed-size byte field from the request bytes.
        """
        if len(self.request_bytes) < self.offset + size:
            raise ValueError(f"Request too short. No valid {field_name} field received.")

        extracted_bytes = struct.unpack(f'<{size}s', self.request_bytes[self.offset:self.offset + size])[0]
        self.offset += size
        return extracted_bytes

    def parse_payload(self):
        """
        Parsing the request payload according to the request type.
        """
        try:
            # Client list or waiting message request
            if self.request_code in [RequestType.CLIENT_LIST_REQUEST.value,
                                     RequestType.RECEIVE_INCOMING_MESSAGES_REQUEST.value]:
                if self.payload_size > 0:
                    raise ValueError(
                        f"Payload size {self.payload_size} is too large for the current request (expected 0).")

            # Register request
            elif self.request_code == RequestType.REGISTER_REQUEST.value:
                self.client_name = self._extract_client_name(RequestFieldsSizes.CLIENT_NAME_SIZE.value)
                self.public_key = self._extract_bytes(RequestFieldsSizes.PUBLIC_KEY_SIZE.value, "Public Key")

            # Public key request
            elif self.request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:
                self.target_client_id = self._extract_bytes(RequestFieldsSizes.CLIENT_ID_SIZE.value, "Client ID")

            else:
                raise ValueError(f"Invalid request code: {self.request_code}")

        except struct.error as e:
            raise ValueError(f"Error unpacking request payload: {e}")
        except Exception as e:
            raise ValueError(f"Error unpacking request payload: {e}")


class Message:
    """
    A general Message class that is responsible for parsing the received message and initializing it with the
    appropriate parameters.
    """

    def __init__(self, message_bytes=b""):
        self.message_header_bytes = message_bytes
        self.target_client_id = None
        self.message_type = None
        self.content_size = None
        self.message_content_bytes = None
        self.message_content = None
        self.offset = 0

        self.parse_message_header()

    def parse_message_header(self):
        """
        Parses the message header from the request bytes and updates the relevant fields.
        """
        try:
            min_message_size = MessageOffset.TO_CLIENT_ID_MESSAGE_SIZE.value
            if len(self.message_header_bytes) < min_message_size:
                raise ValueError(
                    f"Message header is too short. expected {min_message_size} \
                    but got {len(self.message_header_bytes)}.")

            self.target_client_id = self._extract_bytes(self.message_header_bytes,
                                                        MessageOffset.TO_CLIENT_ID_MESSAGE_SIZE.value, "Client ID")
            self.message_type = self._extract_int(self.message_header_bytes, MessageOffset.MESSAGE_TYPE_SIZE.value,
                                                  '<B', "Message type")
            validate_range("Message type", self.message_type, "uint8_t")
            self.content_size = self._extract_int(self.message_header_bytes, MessageOffset.MESSAGE_CONTENT_SIZE.value,
                                                  '<I', "Message content size")
            validate_range("Message content size", self.content_size, "uint32_t")

        except Exception as e:
            raise ValueError(f"Unexpected error while parsing message header bytes: {e}")

    def parse_message_content(self, content):
        """
        Parses the message content bytes received from the server and updates the message content field.
        """
        try:
            self.message_content_bytes = content
            if len(self.message_content_bytes) != self.content_size:
                raise ValueError(f"Mismatch between content size: {self.content_size} and \
                content bytes: {len(self.message_content_bytes)} received.")

            if self.message_type == MessageType.SYMMETRICAL_KEY_REQUEST.value:
                if self.content_size != 0:
                    raise ValueError(f"Invalid message. Symmetrical key request message must be empty, \
                    and content size is {self.content_size} bytes.")

            elif self.message_type == MessageType.SYMMETRICAL_KEY_SEND.value:
                self.message_content = struct.unpack('<128s', self.message_content_bytes[:self.content_size])[0]

            elif self.message_type == MessageType.SEND_TEXT_MESSAGE.value:
                self.message_content = self.message_content_bytes[:self.content_size]

            elif self.message_type == MessageType.SEND_FILE_MESSAGE.value:
                self.message_content = self.message_content_bytes[:self.content_size]

            else:
                raise ValueError(f"Message type: {self.message_type} is invalid.")

        except Exception as e:
            raise ValueError(f"Unexpected error while parsing message content bytes: {e}")

    def _extract_bytes(self, relevant_bytes, size, field_name):
        """
        Utility function that extracts a fixed-size byte field from the request bytes.
        """
        if len(relevant_bytes) < self.offset + size:
            raise ValueError(f"Message too short. No valid {field_name} field received.")

        extracted_bytes = struct.unpack(f'<{size}s', relevant_bytes[self.offset:self.offset + size])[0]
        self.offset += size
        return extracted_bytes

    def _extract_int(self, relevant_bytes, size, fmt, field_name):
        """
        Utility method that extracts an integer (of given size & format) from the request bytes and updates the offset.
        """
        if len(relevant_bytes) < self.offset + size:
            raise ValueError(f"Message too short. No valid {field_name} field received.")

        extracted_value = struct.unpack(fmt, relevant_bytes[self.offset:self.offset + size])[0]

        self.offset += size
        return extracted_value


class Response:
    """
    Response class - responsible for sending a response to the client.
    """
    def __init__(self, sock):
        self.socket = sock
        self.response_code = None
        self.version = VERSION_NUMBER
        self.payload_size = 0
        self.response = None
        self.client_id = None
        self.public_key = None
        self.message_id = None

    def register_response(self, client_id):
        """
        Sends a register response to the client.
        """
        try:
            self.response_code = ResponseType.CLIENT_REGISTER_RESPONSE_SUCCESS.value
            self.payload_size = ResponseFieldsSizes.CLIENT_ID_SIZE.value
            self.response = struct.pack("<BHI 16s", self.version, self.response_code, self.payload_size,
                                        client_id.bytes)

            self.socket.sendall(self.response)
        except Exception as e:
            raise ValueError(f"Error while sending Register response: {e}")

    def client_list_response(self, clients_list):
        """
        Sends a client list response to the client.
        """
        try:
            self.response_code = ResponseType.CLIENT_LIST_RESPONSE_SUCCESS.value
            self.payload_size = len(clients_list) * (
                    ResponseFieldsSizes.CLIENT_ID_SIZE.value + ResponseFieldsSizes.CLIENT_NAME_SIZE.value)
            self.response = struct.pack("<BHI", self.version, self.response_code, self.payload_size)
            self.socket.sendall(self.response)

            for client_id, name in clients_list:
                fmt_id = struct.pack("<16s", client_id)

                name = name.encode("ascii")
                while len(name) < ResponseFieldsSizes.CLIENT_NAME_SIZE.value:
                    name += b'\x00'
                fmt_name = struct.pack("<255s", name)
                self.socket.sendall(fmt_id + fmt_name)
        except Exception as e:
            raise ValueError(f"Error while sending clients list response: {e}")

    def public_key_response(self, target_client_id, public_key):
        """
        Sends a public key response to the client.
        """
        try:
            self.response_code = ResponseType.PUBLIC_KEY_OF_OTHER_CLIENT_RESPONSE_SUCCESS.value
            self.payload_size = ResponseFieldsSizes.CLIENT_ID_SIZE.value + ResponseFieldsSizes.PUBLIC_KEY_SIZE.value
            self.response = struct.pack("<BHI", self.version, self.response_code, self.payload_size)
            self.socket.sendall(self.response)

            self.client_id = struct.pack("<16s", target_client_id)
            self.public_key = struct.pack("<160s", public_key)

            self.socket.sendall(self.client_id + self.public_key)
        except Exception as e:
            raise ValueError(f"Error while sending public key response: {e}")

    def message_sent_response(self, target_client_id, message_id):
        """
        Sends a message sent response to the client.
        """
        try:
            self.response_code = ResponseType.SEND_MESSAGE_RESPONSE_SUCCESS.value
            self.payload_size = ResponseFieldsSizes.CLIENT_ID_SIZE.value + ResponseFieldsSizes.MESSAGE_ID_SIZE.value
            self.response = struct.pack("<BHI", self.version, self.response_code, self.payload_size)
            self.socket.sendall(self.response)

            self.client_id = struct.pack("<16s", target_client_id)
            self.message_id = struct.pack("<I", message_id)
            self.socket.sendall(self.client_id + self.message_id)
        except Exception as e:
            raise ValueError(f"Error while sending message sent response: {e}")

    def fetching_messages_response(self, messages_list):
        """
        Sends a list of waiting messages response to the client.
        """
        try:
            self.response_code = ResponseType.RECEIVE_INCOMING_MESSAGES_RESPONSE_SUCCESS.value

            # Calculating the payload size
            for client_id, message_id, message_type, content in messages_list:
                content = content or b""
                self.payload_size += ResponseFieldsSizes.CLIENT_ID_SIZE.value + \
                                     ResponseFieldsSizes.MESSAGE_ID_SIZE.value + \
                                     ResponseFieldsSizes.MESSAGE_TYPE_SIZE.value + \
                                     ResponseFieldsSizes.MESSAGE_CONTENT_SIZE.value + len(content)

            # Sending the response header
            self.response = struct.pack("<BHI", self.version, self.response_code, self.payload_size)
            self.socket.sendall(self.response)

            # Sending all the messages in a loop
            for (client_id, message_id, message_type, content) in messages_list:
                # Building the message header
                fmt_id = struct.pack("<16s", client_id)
                fmt_message_id = struct.pack("<I", message_id)
                fmt_message_type = struct.pack("<B", message_type)
                content = content or b""
                fmt_message_content_size = struct.pack("<I", len(content))

                header = fmt_id + fmt_message_id + fmt_message_type + fmt_message_content_size

                # Sending the message header
                self.socket.sendall(header)

                # Send message content in chunks
                for i in range(0, len(content), SOCKET_CHUNK_SIZE):
                    chunk = content[i:i + SOCKET_CHUNK_SIZE]
                    self._send_with_retry(self.socket, chunk)

            return True
        except Exception as e:
            raise ValueError(f"Error while sending waiting messages list response: {e}")

    def error_response(self):
        """
        Sends a general error response to the client.
        """
        print("Sending Error Response (code 9000)")
        self.response_code = ResponseType.GENERAL_ERROR_RESPONSE.value
        # Sending the error response
        self.response = struct.pack("<BHI", self.version, self.response_code, self.payload_size)
        self.socket.sendall(self.response)

    def _send_with_retry(self, sock, data):
        """
        Sends all data over a non-blocking socket, handling cases where not all bytes are sent immediately.
        """
        total_sent = 0
        while total_sent < len(data):
            try:
                sent = sock.send(data[total_sent:])  # Attempt to send remaining bytes
                if sent == 0:
                    raise RuntimeError("Socket connection broken")
                total_sent += sent
            except BlockingIOError:
                # ✅ If buffer is full, wait until the socket is writable
                select.select([], [sock], [])  # Wait for socket to be ready before retrying


class Database:
    """
    Database class - responsible for creating and maintaining the database
    that holds the clients and messages tables, which hold all the registered clients
    and all the messages between clients respectively.
    """
    DB_FILENAME = "defensive.db"
    CLIENTS_TABLE_NAME = "clients"
    MESSAGES_TABLE_NAME = "messages"

    def __init__(self):
        self.connection = sqlite3.connect(self.DB_FILENAME)
        self.create_tables()  # Creates the clients and messages tables if they don't exist

    def does_client_exist(self, username: str) -> bool:
        """Checks if the username exists in the database"""
        cursor = self.connection.cursor()
        try:
            # Query to check if the username exists
            cursor.execute(
                f"SELECT COUNT(*) FROM {self.CLIENTS_TABLE_NAME} WHERE name = (?);", (username,))
            result = cursor.fetchone()
            return result[0] > 0  # True if count > 0, otherwise False
        except Exception as e:
            raise ValueError(f"Error checking if client exists in the DB: {e}")
        finally:
            cursor.close()

    def get_client_by_name(self, username: str):
        """Get a client by their username."""
        cursor = self.connection.cursor()
        try:
            self.validate_username(username)  # Validate the given username
            cursor.execute(
                f"SELECT * FROM {self.CLIENTS_TABLE_NAME} WHERE name = ?;", (username,)
            )
            rows = cursor.fetchall()
        except Exception as e:
            print(f"ERROR: Failed to retrieve client by username '{username}': {e}")
            return None  # Return `None` to indicate an error occurred
        finally:
            cursor.close()  # Ensure the cursor is always closed

        if not rows:
            return None  # Return `None` if no client is found
        return rows[0]  # Return the first matching row

    def insert_message(self, to_client_id, from_client_id, message_type, content):
        """Insert a message into the DB Messages table"""
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"INSERT INTO {self.MESSAGES_TABLE_NAME} (to_client, from_client, type, content) VALUES (?, ?, ?, ?);",
                (to_client_id, from_client_id, message_type, content)
            )
            self.connection.commit()
            message_id = cursor.lastrowid
            return message_id
        except Exception as e:
            raise ValueError(f"ERROR: unable to insert message into DB: {e}")
        finally:
            cursor.close()

    def get_public_key_by_id(self, client_id: bytes) -> bytes:
        """
        Get the public key of a client by their ID.
        Returns the public key as bytes, or None if the client does not exist.
        """
        cursor = self.connection.cursor()
        try:
            # Query the database for the public key
            cursor.execute(
                f"SELECT public_key FROM {self.CLIENTS_TABLE_NAME} WHERE id = ?;", (client_id,)
            )
            result = cursor.fetchone()
        except Exception as e:
            raise ValueError(f"ERROR: Failed to fetch public key for ID '{client_id}': {e}")
        finally:
            cursor.close()  # Ensure the cursor is closed

        # Check if the client exists
        if result is None:
            raise ValueError(f"WARNING: No client found with ID '{client_id}'.")

        return result[0]  # Return the public key as bytes

    def insert_client(self, username, public_key):
        """
        Insert a new client into the DB.
        """
        cursor = self.connection.cursor()
        try:
            # Validate the username
            self.validate_username(username)

            # Ensure the client doesn't already exist
            if self.does_client_exist(username):
                raise ValueError(f"Client '{username}' already exists in the database.")

            # Generate a server-side client ID
            server_client_id = uuid.uuid4()

            # Insert the client into the database
            cursor.execute(
                f"INSERT INTO {self.CLIENTS_TABLE_NAME} (id, name, public_key, last_seen) VALUES (?, ?, ?, ?);",
                (server_client_id.bytes, username, public_key,
                 datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            self.connection.commit()
            return server_client_id

        except Exception as e:
            raise ValueError(f"Error inserting new client into DB - {e}")
        finally:
            cursor.close()

    def validate_username(self, username: str):
        """
        Validates the username entered, according to the protocol standards.
        """
        if len(username) >= RequestFieldsSizes.CLIENT_NAME_SIZE.value or len(username) < 1:
            raise ValueError("Invalid username. The username must be between 1 and 254 characters.")
        if not username.isascii():
            raise ValueError("Invalid username. The username must not contain any special characters (ASCII only).")

    def fetch_all_registered_clients(self, username: str) -> list:
        """Fetch all registered clients' usernames except the one supplied in the parameter."""
        cursor = self.connection.cursor()
        try:
            cursor.execute(f"SELECT id, name FROM {self.CLIENTS_TABLE_NAME} WHERE name != ?;", (username,))
            results = cursor.fetchall()
            return results
        except Exception as e:
            raise ValueError(f"Error fetching registered clients: {e}")
        finally:
            cursor.close()

    def update_last_seen(self, client_id):
        """
        Updates the last_seen field for a given username in the clients table.
        """
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"UPDATE {self.CLIENTS_TABLE_NAME} SET last_seen = ? WHERE id = ?;",
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), client_id)
            )
            self.connection.commit()
        except Exception as e:
            raise ValueError(f"Error updating last_seen for {self.get_username_by_uuid(client_id)}: {e}")
        finally:
            cursor.close()

    def get_username_by_uuid(self, client_id: bytes) -> Any | None:
        """
        Get a client's username by their UUID (id).
        Returns the username as a string or None if the client does not exist.
        """
        cursor = self.connection.cursor()
        try:
            # Query the database for the username
            cursor.execute(
                f"SELECT name FROM {self.CLIENTS_TABLE_NAME} WHERE id = ?;", (client_id,))
            result = cursor.fetchone()
        except Exception as e:
            print(f"ERROR: Failed to fetch username for ID '{client_id}': {e}")
            return None  # Return None in case of an error
        finally:
            cursor.close()  # Ensure the cursor is closed

        # Check if the user exists
        if result is None:
            print(f"WARNING: No client found with ID '{client_id}'.")
            return None

        return result[0]  # Return the username as a string

    def fetch_messages_to_client(self, to_client_id: bytes) -> list:
        """
        Fetch all messages for a given client (using his client ID).
        Returns a list of [message_id, from_client_id, message_type, content] tuples for each message.
        """
        cursor = self.connection.cursor()
        messages = []
        try:
            # Fetch all messages for the given to_client ID
            cursor.execute(
                f"SELECT id, from_client, type, content FROM {self.MESSAGES_TABLE_NAME} WHERE to_client = ?;",
                (to_client_id,)
            )
            results = cursor.fetchall()

            # Process each message
            for message_id, from_client_id, message_type, content in results:
                username = self.get_username_by_uuid(from_client_id)  # Convert UUID to username
                if username is not None:
                    messages.append([from_client_id, message_id, message_type, content])

        except Exception as e:
            raise ValueError(f"ERROR: Failed to fetch messages destined to client \
            '{self.get_username_by_uuid(to_client_id)}': {e}")
        finally:
            cursor.close()  # Ensure the cursor is closed
        return messages

    def delete_messages_to_client(self, to_client_id: bytes) -> None:
        """
        Delete all the messages destined for a client.
        """
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"DELETE FROM {self.MESSAGES_TABLE_NAME} WHERE to_client = ?;", (to_client_id,)
            )
            self.connection.commit()
            print(f"Deleted all messages for client '{self.get_username_by_uuid(to_client_id)}'.")
        except Exception as e:
            print(f"ERROR: Failed to delete messages for to_client ID '{to_client_id}': {e}")
        finally:
            cursor.close()  # Ensure the cursor is closed

    def create_tables(self):
        """
        Creates the clients and messages tables in the DB if they don't exist.
        """
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS {self.CLIENTS_TABLE_NAME} (
                        id BLOB(16) PRIMARY KEY,
                        name varchar(255) NOT NULL,
                        public_key BLOB(160),
                        last_seen DATETIME
                    )"""
            )
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS {self.MESSAGES_TABLE_NAME}(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        to_client BLOB(16), 
                        from_client BLOB(16),
                        type INTEGER,
                        content BLOB
                    )"""
            )
            print("Clients and Messages tables were created successfully, or already exist in the database")
        except Exception as e:
            print(f"ERROR: Failed to create SQL tables: {e}")
            raise
        finally:
            cursor.close()  # Ensure the cursor is closed


def validate_range(var_name: str, number: int, uint_type: Literal["uint8_t", "uint16_t", "uint32_t"]) -> None:
    """
    Validates if a given number is within the valid range for an unsigned integer type.
    Used to validate unsigned integer fields received from the client through the socket.

    Parameters:
    - var_name (str): The name of the variable being validated, used for error messages.
    - number (int): The number to validate.
    - uint_type (str): The unsigned integer type as a string. Accepted values are "uint8_t", "uint16_t", "uint32_t".

    Raises:
    - ValueError: If the `uint_type` is invalid or the `number` is outside the range for the specified type.
    """
    range_lookup = {
        "uint8_t": lambda: (0, 0xFF),
        "uint16_t": lambda: (0, 0xFFFF),
        "uint32_t": lambda: (0, 0xFFFFFFFF),
    }

    if uint_type not in range_lookup:
        raise ValueError(f"Invalid type specified: {uint_type}")

    min_val, max_val = range_lookup[uint_type]()
    if number < min_val or number > max_val:
        raise ValueError(f"{var_name} ({number}) is not in the valid range for {uint_type} [{min_val}, {max_val}].")


def main():
    """The main function, creating the user_id for the runtime requests sequence, parsing the info_files and then
    calls the script."""
    server = Server()
    server.run()


if __name__ == "__main__":
    main()
