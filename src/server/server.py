"""
File: server.py
Author: Omri Peretz
Date: January 2025
Assignment: Maman 15
Course: Defensive Systems Programming

Description: This file is a client program written in Python, that is a python server that manages text transfers
between different clients. The client and server communicate over TCP, with a compatible, agreed upon protocol. The
data is being sent in little endian format. TODO change this <<<<<<<<<

The client can send the following requests: TODO change this <<<<<<<<<
- 100: Save a file for backup in the server
- 200: Retrieve a file from the server
- 201: Delete a file from the server
- 202: List all files in the user's directory in the server

The server will do the operation and respond with the following statuses: TODO change this <<<<<<<<<
- 201: Success: File retrieved from the server
- 211: Success: File list created and retrieved from the server
- 212: Success: File was backed up / deleted
- 1001: Error: No such file exists in the server for the client
- 1002: Error: No files exist on the server for this client
- 1003: Error: General server error

"""
# import statements
import socket
import selectors
import struct
import uuid
from datetime import datetime
from enum import Enum
import sqlite3
import os
from typing import Any

# general constants:
VERSION_NUMBER = 2


class MessageType(Enum):
    """
    Each message contains:
    - Client ID
    - Message Type
    - Content size (message size)
    - Message content
    This class focuses on the different message types.
    """
    SYMMETRICAL_KEY_REQUEST = 1  # Message content is empty and Content Size = 0
    SYMMETRICAL_KEY_SEND = 2  # Message content has a symmetrical key, encrypted by the public key of the target client
    SEND_TEXT_MESSAGE = 3  # Message content contains text encrypted by the symmetrical key
    SEND_FILE_MESSAGE = 4


class MessageOffset(Enum):
    MIN_MESSAGE_SIZE = 21
    TO_CLIENT_ID_MESSAGE_SIZE = 16
    MESSAGE_TYPE_SIZE = 1
    MESSAGE_CONTENT_SIZE = 4
    FROM_CLIENT_MESSAGE_SIZE = 16


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
    CLIENT_NAME_SIZE = 255
    PUBLIC_KEY_SIZE = 160
    CLIENT_ID_SIZE = 16
    MESSAGE_TYPE_SIZE = 1
    CONTENT_SIZE_SIZE = 4


class ResponseFieldsSizes(Enum):
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
    SYMMETRIC_KEY_SIZE = 16  # bytes
    PRIVATE_KEY_SIZE = 128  # bytes
    PUBLIC_KEY_SIZE = 160  # bytes
    ENCRYPTED_SYMMETRIC_KEY_SIZE = 128  # bytes


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
    Here we define the different response types. The general structure is:
    - Server version (1 byte)
    - Response Code (2 bytes)
    - Payload Size (4 bytes)
    - Payload (changing)
    """
    CLIENT_REGISTER_REQUEST_SUCCESS = 2100  # Payload will be the Client ID
    CLIENT_LIST_REQUEST_SUCCESS = 2101  # Payload will contain the Client ID, + \
    # followed by all client names but the requesting Client.
    PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST_SUCCESS = 2102  # client ID + public key
    SEND_MESSAGE_REQUEST_SUCCESS = 2103  # Client ID + Message ID
    RECEIVE_INCOMING_MESSAGES_SUCCESS = 2104  # Client ID + Message ID + Message Type + \
    # Message Size + Message content (ONE MESSAGE AFTER THE OTHER)
    GENERAL_ERROR = 9000  # Payload field is empty, Payload size = 0


# TODO add a validate username function!!!!!!!!!!!!!
def validate_username(username: str):
    if len(username) > RequestFieldsSizes.CLIENT_NAME_SIZE.value:
        raise ValueError("Invalid username. The username must not exceed 255 characters.")
    if not username.isascii():
        raise ValueError("Invalid username. The username must not contain any special characters.")


class Database:
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
            print(f"Error: {e}")
            return False
        finally:
            cursor.close()

    def get_client_by_name(self, username: str):
        """Get a client by their username."""
        cursor = self.connection.cursor()
        try:
            validate_username(username)  # Validate the given username
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

    # TODO validate all message fields inside of the message class
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
            print(f"ERROR: unable to insert message into DB: {e}")
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
            print(f"ERROR: Failed to fetch public key for ID '{client_id}': {e}")
            return None  # Return None in case of an error
        finally:
            cursor.close()  # Ensure the cursor is closed

        # Check if the client exists
        if result is None:
            print(f"WARNING: No client found with ID '{client_id}'.")
            return None

        return result[0]  # Return the public key as bytes

    def insert_client(self, username, public_key):
        """
        Insert a new client into the DB.
        """
        cursor = self.connection.cursor()
        try:
            # Validate the username
            validate_username(username)

            # Ensure the client doesn't already exist
            if self.does_client_exist(username):
                raise ValueError(f"Client '{username}' already exists in the database.")

            # Generate a server-side client ID
            server_client_id = uuid.uuid4()

            # TODO don't insert the datetime here, just call the function that does it in the end, or generally whenever there's a database access.
            # Insert the client into the database
            cursor.execute(
                f"INSERT INTO {self.CLIENTS_TABLE_NAME} (id, name, public_key, last_seen) VALUES (?, ?, ?, ?);",
                (server_client_id.bytes, username, bytes(RequestFieldsSizes.PUBLIC_KEY_SIZE.value),
                 datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            self.connection.commit()

            # Optionally update the public key
            if public_key:
                self.insert_public_key(username, public_key)

            return server_client_id

        except ValueError as ve:
            print(f"Validation error: {ve}")
            raise
        except Exception as e:
            print(f"Error inserting new client into DB: {e}")
            raise
        finally:
            cursor.close()

    def insert_public_key(self, username: str, public_key: bytes):
        """
        Insert or update the public key for a specific client in the database.
        """
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"UPDATE {self.CLIENTS_TABLE_NAME} SET public_key = ? WHERE name = ?;",
                (public_key, username)
            )
            if cursor.rowcount == 0:  # Check if the update affected any rows
                raise ValueError(f"Client '{username}' does not exist in the database.")
            self.connection.commit()
            print(f"Public key updated for client '{username}'.")
        except ValueError as e:
            print(f"Error: {e}")
            raise
        except Exception as e:
            print(f"Error updating public key for client '{username}': {e}")
        finally:
            cursor.close()

    def fetch_all_registered_clients(self, username: str) -> list:
        """Fetch all registered clients' usernames except the one specified."""
        cursor = self.connection.cursor()
        try:

            cursor.execute(f"SELECT id, name FROM {self.CLIENTS_TABLE_NAME};")
            all_users = cursor.fetchall()
            print(f"DEBUG: All Users in DB: {all_users}")

            cursor.execute(f"SELECT id, name FROM {self.CLIENTS_TABLE_NAME} WHERE name != ?;", (username,))
            results = cursor.fetchall()

            print(f"DEBUG: Excluding '{username}', Found: {results}")
            return results
        except Exception as e:
            print(f"Error fetching registered clients: {e}")
            return []
        finally:
            cursor.close()

    def update_last_seen(self, username: str):
        """
        Updates the last_seen field for a given username in the clients table.
        """
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"UPDATE {self.CLIENTS_TABLE_NAME} SET last_seen = ? WHERE name = ?;",
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username)
            )
            self.connection.commit()
        except Exception as e:
            print(f"Error updating last_seen for {username}: {e}")
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
            print(f"WARNING: No client found with id '{client_id}'.")
            return None

        return result[0]  # Return the username as a string

    def fetch_messages_to_client(self, to_client_id: bytes) -> list:
        """
        Fetch all messages for a given to_client ID.
        Returns a list of [username, content] for each message.
        Deletes the messages after fetching them.
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

            # Delete the messages after fetching
            self.delete_messages_to_client(to_client_id)
        except Exception as e:
            print(f"ERROR: Failed to fetch messages for to_client ID '{to_client_id}': {e}")
        finally:
            cursor.close()  # Ensure the cursor is closed

        return messages

    def delete_messages_to_client(self, to_client_id: bytes) -> None:
        """
        Delete all messages for a given to_client ID.
        """
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"DELETE FROM {self.MESSAGES_TABLE_NAME} WHERE to_client = ?;", (to_client_id,)
            )
            self.connection.commit()
            print(f"Deleted all messages for to_client ID '{to_client_id}'.")
        except Exception as e:
            print(f"ERROR: Failed to delete messages for to_client ID '{to_client_id}': {e}")
        finally:
            cursor.close()  # Ensure the cursor is closed

    def create_tables(self):
        try:
            cursor = self.connection.cursor()
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
            print("Tables created successfully, or already exist")
        except Exception as e:
            print(f"ERROR: Failed to create tables: {e}")
        finally:
            cursor.close()  # Ensure the cursor is closed


class Message:
    """
    A general Message class that is responsible for parsing the received message and initializing it with the
    appropriate parameters.
    """

    # Message types
    SYMMETRICAL_KEY_REQUEST_MESSAGE = 1
    SYMMETRICAL_KEY_SEND_MESSAGE = 2
    TEXT_SEND_MESSAGE = 3
    FILE_SEND_MESSAGE = 4

    def __init__(self, message_bytes=b""):
        self.message_header_bytes = message_bytes
        self.target_client_id = None
        self.message_type = None
        self.content_size = None
        self.message_content_bytes = None
        self.message_content = None
        self.offset = 0

        self.parse_message_header()
        # self.parse_message()

    def _extract_bytes(self, relevant_bytes, size, field_name):
        """Extracts a fixed-size byte field from the request bytes."""
        if len(relevant_bytes) < self.offset + size:
            raise ValueError(f"Message too short. No valid {field_name} field received.")

        extracted_bytes = struct.unpack(f'<{size}s', relevant_bytes[self.offset:self.offset + size])[0]
        self.offset += size
        return extracted_bytes

    def _extract_int(self, relevant_bytes, size, fmt, field_name):
        """Extracts an integer (of given size & format) from the request bytes and updates the offset."""
        if len(relevant_bytes) < self.offset + size:
            raise ValueError(f"Message too short. No valid {field_name} field received.")

        extracted_value = struct.unpack(fmt, relevant_bytes[self.offset:self.offset + size])[0]
        self.offset += size
        return extracted_value

    def parse_message_header(self):
        """
        Parses the message header from the request bytes and updates the relevant fields.
        """
        try:
            min_message_size = MessageOffset.TO_CLIENT_ID_MESSAGE_SIZE.value
            if len(self.message_header_bytes) < min_message_size:
                raise ValueError(f"Message header is too short. expected {min_message_size} but got {len(self.message_header_bytes)}.")

            self.target_client_id = self._extract_bytes(self.message_header_bytes, MessageOffset.TO_CLIENT_ID_MESSAGE_SIZE.value, "Client ID")
            self.message_type = self._extract_int(self.message_header_bytes, MessageOffset.MESSAGE_TYPE_SIZE.value, '<B', "Message type")
            self.content_size = self._extract_int(self.message_header_bytes, MessageOffset.MESSAGE_CONTENT_SIZE.value, '<I', "Message content size")

        except Exception as e:
            print(f"Unexpected error while parsing basic message header bytes: {e}")
            raise

    def parse_message_content(self, content):
        """
        Parses the message content bytes received from the server and updates the message content field.
        :param content: TODO delete this or make all of the functions and classes like this.
        :return:
        """
        try:
            self.message_content_bytes = content
            if len(self.message_content_bytes) != self.content_size:
                raise ValueError(f"Mismatch between content size: {self.content_size} and \
                content bytes: {len(self.message_content_bytes)} received.")

            if self.message_type == self.SYMMETRICAL_KEY_REQUEST_MESSAGE:
                if self.content_size != 0:
                    raise ValueError(f"Invalid message. Symmetrical key request message must be empty, \
                    and content size is {self.content_size} bytes.")

            elif self.message_type == self.SYMMETRICAL_KEY_SEND_MESSAGE:
                self.message_content = struct.unpack('<128s', self.message_content_bytes[:self.content_size])[0]

            elif self.message_type == self.TEXT_SEND_MESSAGE:
                self.message_content = self.message_content_bytes[:self.content_size]
                print("DEBUG: ", self.message_content)
                print("DEBUG: ", len(self.message_content))

                # todo same as above, validate length matching and correct type etc...

            elif self.message_type == self.FILE_SEND_MESSAGE:
                # TODO change this to be like the above.
                self.message_content = self.message_content_bytes[:self.content_size]

            else:
                raise ValueError(f"Message type: {self.message_type} is invalid.")

        except Exception as e:
            print(f"Unexpected error while parsing message content bytes: {e}")
            raise

class Request:
    def __init__(self, request_bytes):
        self.request_bytes = request_bytes
        self.client_id = None
        self.client_version = None
        self.request_code = None
        self.offset = 0
        self.payload_size = None

        self.parse_request_header()  # Initializing all the fields above.

        """different payload fields, depending on the request (601 and 604 are empty):"""
        if self.request_code == RequestType.REGISTER_REQUEST.value:  # case 600
            self.client_name = None
            self.public_key = None
        elif self.request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:  # case 602
            self.target_client_id = None
        elif self.request_code == RequestType.SEND_MESSAGE_REQUEST.value:  # case 603
            self.message = None

    def parse_request_header(self):
        """Parses the request that came from the client and calls the appropriate functions"""
        try:
            min_size = RequestOffset.MIN_REQUEST_SIZE.value
            # The minimum size of a request is 23 bytes (client id + version + code + payload size)
            if len(self.request_bytes) < min_size:
                raise ValueError(
                    f"Request too short. Expected at least {min_size} bytes, got {len(self.request_bytes)}.")

            # Gather all of the relevant fields of a basic request
            self.client_id = self.extract_bytes(RequestOffset.CLIENT_ID_SIZE.value, "Client ID")
            self.client_version = self._extract_int(RequestOffset.CLIENT_VERSION_SIZE.value, "<B", "Client Version")
            self.request_code = self._extract_int(RequestOffset.REQUEST_CODE_SIZE.value, "<H", "Request Code")
            self.payload_size = self._extract_int(RequestOffset.REQUEST_PAYLOAD_SIZE.value, "<I", "Payload Size")

            # validate_range("version", server_version, "uint8_t") TODO add this!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            # self.validate_status(status)

            # TODO add length validation for all "size" fields followed by payload, like in the next example:
            """
            # Skip the filename of `name_len` bytes
            filename_received = response[offset:offset + name_len].decode('ascii')
            offset += name_len

            # validating the filename's length, in comparison to the filename length field. if len(filename_received) 
            != name_len: raise ValueError( f"Received filename's length is:({len(filename_received)}), does not match 
            name_len ({name_len}) field.")

            if status == Status.FILE_DELETED_OR_BACKEDUP_SUCCESS.value:  # File delete or backup request is successful:
                if request_operation == Operation.UPLOAD_FILE.value:  # file upload message
                    print(
                        f"Operation {request_operation} is successful: File {filename_received} was sent and backed up in the server in the correct user folder.")
                elif request_operation == Operation.DELETE_FILE.value:  # file delete message
                    print(
                        f"Operation {request_operation} is successful: File {filename_received} was deleted from the user folder in the server.")

                print()  # print a new line
                return

            # validating the payload size field
            if len(response) < offset + Offset.FILE_SIZE.value:
                raise ValueError(
                    "Response is too short to be valid, invalid payload size was returned from the server.")

                # Read `payload_size` (4 bytes, little-endian)
            payload_size, = struct.unpack('<I', response[offset:offset + Offset.FILE_SIZE.value])
            offset += Offset.FILE_SIZE.value

            # Read `payload_size` bytes
            payload = response[offset:offset + payload_size];


            # Validating the payload's size that was received matches the payload_size field.
            if len(payload) != payload_size:
                raise ValueError(
                    f"Payload size received: ({len(payload)}) does not match payload_size field ({payload_size}).")

            if status == Status.FILE_LIST_SENT_SUCCESS.value:  # File list request is successful,print the list of files.
                payload = payload.decode('ascii');
                filename_list = payload.split('\n')
                print(f"Operation {request_operation} is successful: retrieving the list of client file names...")
                print("List of files:")
                for filename in filename_list:
                    if filename.strip():  # Avoid empty strings
                        print(f"- {filename}")
            elif status == Status.FILE_RETRIEVED_SUCCESS.value:  # File retrieval request is successful, save the file in the current directory.
                # Save the file as "tmp" in the current directory
                with open("tmp", "wb") as file:
                    file.write(payload)
                print(
                    f"Operation {request_operation} is successful: File '{filename_received}' was retrieved and saved as 'tmp' in the client.py folder.")
            """
            print()  # print a new line
            return

        except struct.error as e:
            print(f"Error unpacking request: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def _extract_int(self, size, fmt, field_name):
        """Extracts an integer (of given size & format) from the request bytes and updates the offset."""
        if len(self.request_bytes) < self.offset + size:
            raise ValueError(f"Request too short. No valid {field_name} field received.")

        extracted_value = struct.unpack(fmt, self.request_bytes[self.offset:self.offset + size])[0]
        self.offset += size
        return extracted_value

    def extract_client_name(self, size):
        "Extracts the client name from the request bytes, removing the null padding."
        if len(self.request_bytes) < self.offset + size:
            raise ValueError("Request is too short, no valid client name was received")

        name_bytes = struct.unpack("<255s", self.request_bytes[self.offset:self.offset + size])
        self.offset += size
        name = name_bytes[0]
        name = name.split(b'\x00', 1)[0]
        name = name.decode("ascii")
        return name

    def extract_bytes(self, size, field_name):
        """Extracts a fixed-size byte field from the request bytes."""
        if len(self.request_bytes) < self.offset + size:
            raise ValueError(f"Request too short. No valid {field_name} field received.")

        extracted_bytes = struct.unpack(f'<{size}s', self.request_bytes[self.offset:self.offset + size])[0]
        self.offset += size
        return extracted_bytes

    def parse_payload(self):
        """Parsing the payload according to the request type"""
        try:
            # Client list or waiting message request
            if self.request_code in [RequestType.CLIENT_LIST_REQUEST.value,
                                     RequestType.RECEIVE_INCOMING_MESSAGES_REQUEST.value]:
                if self.payload_size > 0:
                    raise ValueError(
                        f"Payload size {self.payload_size} is too large for the current request (expected 0).")

            # Register request
            elif self.request_code == RequestType.REGISTER_REQUEST.value:
                self.client_name = self.extract_client_name(RequestFieldsSizes.CLIENT_NAME_SIZE.value)
                self.public_key = self.extract_bytes(RequestFieldsSizes.PUBLIC_KEY_SIZE.value, "Public Key")

            # Public key request
            elif self.request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:
                self.target_client_id = self.extract_bytes(RequestFieldsSizes.CLIENT_ID_SIZE.value, "Client ID")

            else:
                raise ValueError(f"Invalid request code: {self.request_code}")

        except struct.error as e:
            print(f"Error unpacking request payload: {e}")
            raise
        except Exception as e:
            print(f"Error unpacking request payload: {e}")
            raise


"""
class Request:

    def __init__(self, buffer: bytes):
        if len(buffer) < REQUEST_MIN_LEN:
            raise ValueError(
                f"Invalid request length {len(buffer)} < {REQUEST_MIN_LEN}"
            )
        self.client_id = buffer[:CLIENT_ID_LEN]
        buffer = buffer[CLIENT_ID_LEN:]
        header_remaining_len = 7
        self.version, self.code, self.payload_size = struct.unpack(
            "<BHI", buffer[:header_remaining_len]
        )
        self.code = RequestCode(self.code)
        validate_request_code(self.code)
        validate_range("payload_size", self.payload_size, "uint32_t")
        validate_range("version", self.version, "uint8_t")
        buffer = buffer[header_remaining_len:]
        if len(buffer) != self.payload_size:
            raise ValueError(
                f"Invalid payload length {len(buffer)} != {self.payload_size}"
            )
        self.payload = buffer
"""


class ClientManager:
    CHUNK_SIZE = 1024

    def __init__(self, conn, db, sel):
        self.socket = conn
        self.sel = sel
        self.request = None
        self.db = db
        self.client_id = None  # TODO maybe delete it?
        self.username = None

    def receive_exact_bytes(self, num_bytes):
        """Reads exactly num_bytes from the socket, making sure all data is received"""
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
            raise ValueError("Error parsing message from client: ")

    def receive_and_process_request(self):
        """
        Receive data from the socket and process it into a Request object.
        """
        try:
            request_bytes = self.receive_exact_bytes(RequestOffset.MIN_REQUEST_SIZE.value)
            if not request_bytes:
                raise ValueError("Request is empty")

            self.request = Request(request_bytes)

            if self.request.request_code == RequestType.SEND_MESSAGE_REQUEST.value:
                self.process_message_request()
                return True

            payload_size = self.request.payload_size
            if payload_size > 0:
                payload_bytes = self.receive_exact_bytes(payload_size)
                self.request.request_bytes = request_bytes + payload_bytes
                self.request.parse_payload()

            return True
        except socket.error as e:
            raise

    def handle_request(self, sock, mask):
        """
         Receive the request bytes and parse them using receive_and_process_request().
         Then, handle the request logic, and call the correct response type.
        """
        response = Response(self.socket)
        try:
            self.receive_and_process_request()
            print("Finished parsing request")

            request_code = self.request.request_code
            if request_code == RequestType.CLIENT_LIST_REQUEST.value:
                self.client_list_request()
            elif request_code == RequestType.RECEIVE_INCOMING_MESSAGES_REQUEST.value:
                self.incoming_messages_request()
            elif request_code == RequestType.REGISTER_REQUEST.value:
                self.register_request()
            elif request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:
                self.public_key_other_client_request()
            elif request_code == RequestType.SEND_MESSAGE_REQUEST.value:
                self.send_message_request()
        except Exception as e:
            print(f"Error while handling request: {e}")
            response.error_response()
        finally:
            self.db.update_last_seen(
                self.username)  # todo maybe it's not here??? maybe it's better in the top of the function????

    # TODO add more error handling here???????????
    def client_list_request(self):
        response = Response(self.socket)
        name = self.db.get_username_by_uuid(self.request.client_id)
        clients_list = self.db.fetch_all_registered_clients(name)
        print(clients_list)
        response.client_list_response(clients_list)

    def incoming_messages_request(self):
        messages_list = self.db.fetch_messages_to_client(self.request.client_id)
        response = Response(self.socket)
        response.fetching_messages_response(messages_list)

    def register_request(self):
        response = Response(self.socket)

        if not self.db.does_client_exist(self.username):
            server_client_id = self.db.insert_client(self.request.client_name, self.request.public_key)
            response.register_response(server_client_id)
        else:
            response.error_response()
            raise ValueError(f"Username '{self.username}' already exists in the DB.")

    def public_key_other_client_request(self):
        response = Response(self.socket)
        public_key_other_client = self.db.get_public_key_by_id(self.request.target_client_id)
        print(
            f"DEBUG: The public key i'm sending is:\n {public_key_other_client} \n and it's size is: {len(public_key_other_client)}")
        response.public_key_response(self.request.target_client_id, public_key_other_client)

    def send_message_request(self):
        from_client_id = self.request.client_id
        target_client_id = self.request.message.target_client_id
        message_type = self.request.message.message_type
        message_content = self.request.message.message_content

        message_id = self.db.insert_message(target_client_id, from_client_id, message_type, message_content)

        response = Response(self.socket)
        response.message_sent_response(target_client_id, message_id)


class Response:
    CHUNK_SIZE = 1024

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
        self.response_code = ResponseType.CLIENT_REGISTER_REQUEST_SUCCESS.value
        self.payload_size = ResponseFieldsSizes.CLIENT_ID_SIZE.value
        client_id_bytes = client_id.bytes
        self.response = struct.pack("<BHI 16s", self.version, self.response_code, self.payload_size, client_id_bytes)

        self.socket.sendall(self.response)

    def client_list_response(self, clients_list):
        self.response_code = ResponseType.CLIENT_LIST_REQUEST_SUCCESS.value
        self.payload_size = len(clients_list) * (
                ResponseFieldsSizes.CLIENT_ID_SIZE.value + ResponseFieldsSizes.CLIENT_NAME_SIZE.value)
        self.response = struct.pack("<BHI", self.version, self.response_code, self.payload_size)
        self.socket.sendall(self.response)

        for id, name in clients_list:
            fmt_id = struct.pack("<16s", id)

            name = name.encode("ascii")
            while len(name) < ResponseFieldsSizes.CLIENT_NAME_SIZE.value:
                name += b'\x00'
            fmt_name = struct.pack("<255s", name)
            self.socket.sendall(fmt_id + fmt_name)

    def public_key_response(self, target_client_id, public_key):
        self.response_code = ResponseType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST_SUCCESS.value
        self.payload_size = ResponseFieldsSizes.CLIENT_ID_SIZE.value + ResponseFieldsSizes.PUBLIC_KEY_SIZE.value
        self.response = struct.pack("<BHI", self.version, self.response_code, self.payload_size)
        self.socket.sendall(self.response)

        self.client_id = struct.pack("<16s", target_client_id)
        self.public_key = struct.pack("<160s", public_key)
        print(
            f"DEBUG: The public key i'm sending after packing is:\n {self.public_key} \n and it's size is: {len(self.public_key)}")

        self.socket.sendall(self.client_id + self.public_key)

    def message_sent_response(self, target_client_id, message_id):
        self.response_code = ResponseType.SEND_MESSAGE_REQUEST_SUCCESS.value
        self.payload_size = ResponseFieldsSizes.CLIENT_ID_SIZE.value + ResponseFieldsSizes.MESSAGE_ID_SIZE.value
        self.response = struct.pack("<BHI", self.version, self.response_code, self.payload_size)
        self.socket.sendall(self.response)

        self.client_id = struct.pack("<16s", target_client_id)
        self.message_id = struct.pack("<I", message_id)
        self.socket.sendall(self.client_id + self.message_id)

    def fetching_messages_response(self, messages_list):
        self.response_code = ResponseType.RECEIVE_INCOMING_MESSAGES_SUCCESS.value

        # Calculating the payload size
        for client_id, message_id, message_type, content in messages_list:
            content = content or b""
            self.payload_size += ResponseFieldsSizes.CLIENT_ID_SIZE.value + ResponseFieldsSizes.MESSAGE_ID_SIZE.value + \
                                 ResponseFieldsSizes.MESSAGE_TYPE_SIZE.value + \
                                 ResponseFieldsSizes.MESSAGE_CONTENT_SIZE.value + len(content)

        # TODO DEBUG, REMOvE THIS LATER!!!!!!
        def hexify(data):
            """Convert bytes to a hex string for debugging."""
            return " ".join(f"{b:02X}" for b in data)

        print("DEBUG-------------------------")
        for client_id, message_id, message_type, content in messages_list:
            content = content or b""
            print(f"Client ID: {hexify(client_id)}")
            print(f"Message ID: {message_id:08X}")  # Print as 8-digit hex
            print(f"Message Type: {message_type:02X}")  # Print as 2-digit hex
            print(f"Content size: {len(content)}")  # Print as 2-digit hex
            print(f"Content\n: {hexify(content)}")
            print("-" * 40)
        print("END DEBUG-------------------------")

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

            print("DEBUG Header Sent (Hex):", header.hex())

            # Sending the message header
            self.socket.sendall(header)

            # Sending the message content
            if content is not None:
                for i in range(0, len(content), self.CHUNK_SIZE):
                    chunk = content[i:i + self.CHUNK_SIZE]  # Get a chunk of max CHUNK_SIZE
                    self.socket.sendall(chunk)  # Send the chunk
                    print("DEBUG: Sending chunk ", chunk.hex())

    def error_response(self):
        self.response_code = ResponseType.GENERAL_ERROR.value
        # Sending the error response
        self.response = struct.pack("<BHI", self.version, self.response_code, self.payload_size)
        self.socket.sendall(self.response)


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
                            f"WARNING: Port number in '{self.PORT_FILE_NAME}' is out of valid range ({self.MIN_PORT_NUMBER}-{self.MAX_PORT_NUMBER}): {port}")
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
        print(f"Server is running on {self.host}:{self.port}")

    def _accept_client(self, sock: socket.socket, mask) -> None:
        """Handles new client connections."""
        try:
            conn, addr = sock.accept()
            conn.setblocking(False)
            print(f"New connection from {addr}")

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
                success = client.handle_request(sock, mask)
                if not success:
                    print(f"Client {sock.fileno()} disconnected.")
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
                print(f"DEBUG: Selector woke up, {len(events)} events")  # 🔴 Debug print

                for key, mask in events:
                    callback = key.data  # The registered function (e.g., _accept_client or _read_client) TODO change this comment
                    print(f"DEBUG: Calling {callback.__name__} for {key.fileobj}")  # 🔴 Debug print
                    callback(key.fileobj, mask)  # Call the registered function
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


def main():
    """The main function, creating the user_id for the runtime requests sequence, parsing the info_files and then
    calls the script."""
    server = Server()
    server.run()


if __name__ == "__main__":
    main()
