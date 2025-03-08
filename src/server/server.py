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

    def __init__(self, content_bytes=b"", message_bytes=b""):
        self.content_bytes = content_bytes  # Contains the request bytes
        self.basic_message_bytes = message_bytes
        self.target_client_id = None
        self.message_type = None
        self.content_size = None
        self.message_content_bytes = None
        self.message_content = None

        self.parse_basic_message()
        # self.parse_message()

    def parse_basic_message(self):
        print("DEBUG: basic message bytes = " + str(self.basic_message_bytes))
        if len(self.basic_message_bytes) < MessageOffset.TO_CLIENT_ID_MESSAGE_SIZE.value:
            raise ValueError("Message is too short to be valid. No valid client id field was received.")

        self.target_client_id = struct.unpack('<16s', self.basic_message_bytes[
                                                      : MessageOffset.TO_CLIENT_ID_MESSAGE_SIZE.value])[0]
        offset = MessageOffset.TO_CLIENT_ID_MESSAGE_SIZE.value

        if len(self.basic_message_bytes) < offset + MessageOffset.MESSAGE_TYPE_SIZE.value:
            raise ValueError("Message is too short to be valid. No valid message type field was received.")
        self.message_type = struct.unpack('<B', self.basic_message_bytes[
                                                offset: offset + MessageOffset.MESSAGE_TYPE_SIZE.value])[0]
        offset = offset + MessageOffset.MESSAGE_TYPE_SIZE.value

        if len(self.basic_message_bytes) < offset + MessageOffset.MESSAGE_CONTENT_SIZE.value:
            raise ValueError("Message is too short to be valid. No valid content size field was received.")
        self.content_size = struct.unpack('<I', self.basic_message_bytes[
                                                offset: offset + MessageOffset.MESSAGE_CONTENT_SIZE.value])[0]
        offset = offset + MessageOffset.MESSAGE_CONTENT_SIZE.value

    def parse_message_content(self):
        try:
            """CONTENT SIZE AND CONTENT PARSING"""
            print("DEBUG PRINTS:")
            print(self.message_content_bytes)
            print()
            hex_str = " ".join(f"{byte:02x}" for byte in self.message_content_bytes)
            print(f"Raw Data ({len(self.message_content_bytes)} bytes): {hex_str}")

            if len(self.message_content_bytes) != self.content_size:
                raise ValueError("Message is too short to be valid. No valid content field was received.")

            if self.message_type == self.SYMMETRICAL_KEY_REQUEST_MESSAGE:
                self.symmetrical_key_request_message()
            elif self.message_type == self.SYMMETRICAL_KEY_SEND_MESSAGE:
                self.symmetrical_key_send_message()
            elif self.message_type == self.TEXT_SEND_MESSAGE:
                self.text_send_message()
            elif self.message_type == self.FILE_SEND_MESSAGE:
                self.file_send_message()
            else:
                raise ValueError("No valid message type field was received.")

        except struct.error as e:
            print(f"Error unpacking message payload: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def symmetrical_key_request_message(self):
        """ Handle symmetrical key request messages """
        if self.content_size != 0:
            raise ValueError("Invalid message. Symmetrical key request message must be empty.")

    def symmetrical_key_send_message(self):
        """ Handle symmetrical key send messages """
        # TODO remove this weird check and just check with the message length??
        if len(self.message_content_bytes) != EncryptionKeysSizes.ENCRYPTED_SYMMETRIC_KEY_SIZE.value:
            raise ValueError("Invalid message. Symmetric key send message length must be equal to symmetric key size.")
        offset = 0
        self.message_content = struct.unpack('<128s', self.message_content_bytes[
                                                     offset: offset + EncryptionKeysSizes.ENCRYPTED_SYMMETRIC_KEY_SIZE.value])[0]

        hex_str = " ".join(f"{byte:02x}" for byte in self.message_content)
        print(f"Raw Data ({len(self.message_content)} bytes): {hex_str}")
        print()
        print(self.message_content)

        if len(self.message_content) != self.content_size:
            raise ValueError("Invalid message. Symmetric key send message length must be equal to symmetric key size.")

    def text_send_message(self):
        offset = 0
        self.message_content = self.content_bytes[offset: offset + self.content_size]

        # todo same as above, validate length matching and correct type etc...

    def file_send_message(self):
        offset = 0
        self.message_content = self.content_bytes[offset: offset + self.content_size]


class Request:
    def __init__(self, request_bytes):
        self.request = request_bytes
        self.client_id = None
        self.client_version = None
        self.request_code = None
        self.offset = 0
        self.payload_size = None

        self.parse_basic_request_details()  # Initializing all the fields above.

        """different payload fields, depending on the request (601 and 604 are empty):"""
        if self.request_code == RequestType.REGISTER_REQUEST.value:  # case 600
            self.client_name = None
            self.public_key = None
        elif self.request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:  # case 602
            self.target_client_id = None
        elif self.request_code == RequestType.SEND_MESSAGE_REQUEST.value:  # case 603
            self.message = None

        # self.parse_payload()

    def parse_basic_request_details(self):
        """Parses the request that came from the client and calls the appropriate functions"""
        try:
            # The minimum size of a request is 16 bytes (for the client id field)
            if len(self.request) < RequestOffset.CLIENT_ID_SIZE.value:
                raise ValueError("Request is too short to be valid. No valid Client ID was received.")

            self.offset = RequestOffset.CLIENT_ID_SIZE.value

            # Unpack the request id
            self.client_id = struct.unpack('<16s', self.request[:self.offset])[0]

            # validate_range("version", server_version, "uint8_t") TODO add this!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            # self.validate_status(status)

            if len(self.request) < self.offset + RequestOffset.CLIENT_VERSION_SIZE.value:
                # Check that we received a valid client version
                raise ValueError(
                    "Request is too short to be valid, invalid ToClient ID length was received.")

            # gather the client version
            self.client_version = struct.unpack('<B', self.request[
                                                      self.offset:self.offset + RequestOffset.CLIENT_VERSION_SIZE.value])[0]
            self.offset += RequestOffset.CLIENT_VERSION_SIZE.value

            print(f"DEBUG client version: {self.client_version}")

            if len(self.request) < self.offset + RequestOffset.REQUEST_CODE_SIZE.value:
                # Check that we received a valid request code field
                raise ValueError(
                    "Request is too short to be valid, invalid request code length was received.")

            # gather the request code
            self.request_code = struct.unpack(
                '<H', self.request[self.offset:self.offset + RequestOffset.REQUEST_CODE_SIZE.value])[0]
            self.offset += RequestOffset.REQUEST_CODE_SIZE.value
            print(f"DEBUG request code: {self.request_code}")

            self.payload_size = struct.unpack("<I", self.request[self.offset:self.offset + RequestOffset.REQUEST_PAYLOAD_SIZE.value])[0]
            self.offset += RequestOffset.REQUEST_PAYLOAD_SIZE.value

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

    def parse_payload(self):
        try:
            """
            if len(self.request) < self.offset + RequestOffset.REQUEST_PAYLOAD_SIZE.value:
                raise ValueError("Request is too short to be valid. No valid payload size field was received.")
            """


            # Parse the payload according to the different request types
            if (self.request_code == RequestType.CLIENT_LIST_REQUEST.value or
                    self.request_code == RequestType.RECEIVE_INCOMING_MESSAGES_REQUEST.value):
                if self.payload_size > 0:
                    raise ValueError("Payload size is too large for the current request")
                # TODO maybe i need to validate the payload field as well?

            elif self.request_code == RequestType.REGISTER_REQUEST.value:
                if len(self.request) < self.offset + RequestFieldsSizes.CLIENT_NAME_SIZE.value:
                    raise ValueError("Request is too short to be valid. No valid client name field was received.")
                client_name_bytes = struct.unpack('<255s',
                                                  self.request[self.offset:self.offset +
                                                                           RequestFieldsSizes.CLIENT_NAME_SIZE.value])
                name = client_name_bytes[0]
                name = name.split(b'\x00', 1)[0]
                name = name.decode("ascii")
                self.client_name = name
                self.offset = self.offset + RequestFieldsSizes.CLIENT_NAME_SIZE.value

                if len(self.request) < self.offset + RequestFieldsSizes.PUBLIC_KEY_SIZE.value:
                    raise ValueError("Request is too short to be valid. No valid public key field was received.")
                public_key_bytes = struct.unpack('<160s', self.request[
                                                          self.offset:self.offset + RequestFieldsSizes.PUBLIC_KEY_SIZE.value])
                self.public_key = public_key_bytes[0]

                # TODO register the user and/ or call the other functions

            elif self.request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:
                if len(self.request) < self.offset + RequestFieldsSizes.CLIENT_ID_SIZE.value:
                    raise ValueError("Request is too short to be valid. No valid client id field was received.")
                client_id_bytes = struct.unpack('<16s', self.request[
                                                        self.offset:self.offset + RequestFieldsSizes.CLIENT_ID_SIZE.value])
                self.target_client_id = client_id_bytes[0]

                # TODO call the next functions!

            # elif self.request_code == RequestType.SEND_MESSAGE_REQUEST.value:
            # self.message = Message(self.request[self.offset:self.offset + self.payload_size[0]])

            else:
                raise ValueError("Invalid request code.")

        except struct.error as e:
            print(f"Error unpacking request payload: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")


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
        self.buffer = b""
        self.db = db
        self.client_id = None
        self.username = None
        self.last_active_time = None

    def receive_and_process_request(self):
        """
        Receive data from the socket and process it into a Request object.
        """
        try:
            request_bytes = b""
            request_bytes += self.socket.recv(RequestOffset.MIN_REQUEST_SIZE.value)
            if request_bytes:
                self.request = Request(request_bytes)

            print(f"DEBUG: Total Received Bytes ({len(request_bytes)} bytes): {request_bytes.hex()}")

            if self.request.request_code == RequestType.REGISTER_REQUEST.value:  # case 600
                request_bytes += self.socket.recv(
                    RequestFieldsSizes.CLIENT_NAME_SIZE.value + RequestFieldsSizes.PUBLIC_KEY_SIZE.value)
                self.request.request = request_bytes
                self.request.parse_payload()
            elif self.request.request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:  # case 602
                request_bytes += self.socket.recv(RequestFieldsSizes.CLIENT_ID_SIZE.value)
                self.request.request = request_bytes
                self.request.parse_payload()
            elif self.request.request_code == RequestType.CLIENT_LIST_REQUEST.value or self.request.request_code == RequestType.RECEIVE_INCOMING_MESSAGES_REQUEST.value:
                self.request.parse_payload()
            elif self.request.request_code == RequestType.SEND_MESSAGE_REQUEST.value:  # case 603
                basic_message_bytes = self.socket.recv(MessageOffset.MIN_MESSAGE_SIZE.value)
                print("DEBUG: message_bytes: ", basic_message_bytes.hex())  # Print hex representation of message
                if basic_message_bytes:
                    self.request.message = Message(message_bytes=basic_message_bytes)
                else:
                    # TODO send an error response?????
                    print("ERROR ERROR")
                    return

                content_bytes = b""
                remaining_bytes = self.request.message.content_size

                print("DEBUG: message content size= ", self.request.message.content_size)

                while remaining_bytes > 0:
                    chunk = self.socket.recv(remaining_bytes)
                    if not chunk:
                        raise ValueError("Connection closed before receiving full content.")

                    content_bytes += chunk
                    remaining_bytes -= len(chunk)

                print(f"DEBUG: Content Bytes ({len(content_bytes)} bytes): {content_bytes.hex()}")

                self.request.message.message_content_bytes = content_bytes
                self.request.message.parse_message_content()

            return True
        except socket.error as e:
            print(f"Socket error: {e}")
            return False

    def handle_request(self, sock, mask):
        if not self.receive_and_process_request():
            return  # No valid request received

        print("Finished receiving request bytes")

        if not self.request:
            print("No request to process.")
            return

        request_code = self.request.request_code
        response = Response(self.socket)
        try:
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
            print(f"Request error: {e}")
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
        # name = self.db.get_username_by_uuid(self.request.client_id) TODO delete
        messages_list = self.db.fetch_messages_to_client(self.request.client_id)
        response = Response(self.socket)
        response.fetching_messages_response(messages_list)

    def register_request(self):
        # TODO continue with the logic of registering a new user, and check for a current user already...
        response = Response(self.socket)

        print(f"DEBUG: The public key i received is:\n {self.request.public_key} \n and it's size is: {len(self.request.public_key)}")

        if not self.db.does_client_exist(self.username):
            server_client_id = self.db.insert_client(self.request.client_name, self.request.public_key)
            response.register_response(server_client_id)
        else:
            response.error_response()
            raise ValueError(f"Username '{self.username}' already exists in the DB.")

    def public_key_other_client_request(self):
        response = Response(self.socket)
        public_key_other_client = self.db.get_public_key_by_id(self.request.target_client_id)
        print(f"DEBUG: The public key i'm sending is:\n {public_key_other_client} \n and it's size is: {len(public_key_other_client)}")
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

        for (id, name) in clients_list:
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
        print(f"DEBUG: The public key i'm sending after packing is:\n {self.public_key} \n and it's size is: {len(self.public_key)}")

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
    - Client message handled by ClientManager
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
                for key, mask in events:
                    callback = key.data  # The registered function (e.g., _accept_client or _read_client)
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
