"""
File: server.py
Author: Omri Peretz
Date: January 2025
Assignment: Maman 15
Course: Defensive Systems Programming

Description:
This file is a client program written in Python, that is a python server that manages text transfers between different clients.
The client and server communicate over TCP, with a compatible, agreed upon protocol. The data is being sent in little endian format. TODO change this <<<<<<<<<

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
from datetime import datetime
from enum import Enum
import sqlite3
import os


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
    # SEND_FILE_MESSAGE = 4 TODO bonus feature


class MessageOffset(Enum):
    MIN_MESSAGE_SIZE = 4
    MESSAGE_ID_SIZE = MIN_MESSAGE_SIZE
    TO_CLIENT_MESSAGE_SIZE = 16
    FROM_CLIENT_MESSAGE_SIZE = 16
    TYPE_MESSAGE_SIZE = 1


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
    MIN_REQUEST_SIZE = CLIENT_ID_SIZE
    CLIENT_VERSION_SIZE = 1
    REQUEST_CODE_SIZE = 2
    REQUEST_PAYLOAD_SIZE = 4

class RequestFieldsSizes(Enum):
    CLIENT_NAME_SIZE = 255
    PUBLIC_KEY_SIZE = 160
    CLIENT_ID_SIZE = 16
    MESSAGE_TYPE_SIZE = 1
    CONTENT_SIZE_SIZE = 4

class EncryptionKeysSizes(Enum):
    SYMMETRIC_KEY_SIZE = 128 # bits, 16 bytes
    ASSYMETRIC_KEY_SIZE = 1024 # bits, 128 bytes
    PUBLIC_KEY_SIZE = 160 # bytes


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

class Message:
    """
    A general Message class that is responsible for parsing the received message and initializing it with the appropriate parameters.
    """
    MIN_MESSAGE_LENGTH = RequestFieldsSizes.CLIENT_ID_SIZE.value
    MESSAGE_TYPE_SIZE = 1
    MESSAGE_CONTENT_SIZE = 4

    # Message types
    SYMMETRICAL_KEY_REQUEST_MESSAGE = 1
    SYMMETRICAL_KEY_SEND_MESSAGE = 2
    TEXT_SEND_MESSAGE = 3
    #FILE_SEND_MESSAGE = 4 todo add this feature!

    def __init__(self, request):
        self.request = request  # Contains the request bytes
        self.target_client_id = None
        self.message_type = None
        self.content_size = None
        self.message_content = None

        self.parse_message()

    def parse_message(self):
        try:
            offset = 0
            if len(self.request) < self.MIN_MESSAGE_LENGTH.value:
                raise ValueError("Message is too short to be valid. No valid client id field was received.")

            self.target_client_id = struct.unpack('<16s', self.request[
                                                    : self.MIN_MESSAGE_LENGTH.value])
            offset = self.MIN_MESSAGE_LENGTH.value

            if len(self.request) < offset + self.MESSAGE_TYPE_SIZE.value:
                raise ValueError("Message is too short to be valid. No valid message type field was received.")
            self.message_type = struct.unpack('<B', self.request[
                                                   offset : offset + self.MESSAGE_TYPE_SIZE.value])
            offset = offset + self.MESSAGE_TYPE_SIZE.value

            if self.message_type == self.SYMMETRICAL_KEY_REQUEST_MESSAGE.value:
                self.symmetrical_key_request_message(offset)
            elif self.message_type == self.SYMMETRICAL_KEY_SEND_MESSAGE.value:
                self.symmetrical_key_send_message(offset)
            elif self.message_type == self.TEXT_SEND_MESSAGE.value:
                self.text_send_message(offset)
            else:
                raise ValueError("No valid message type field was received.")


            """CONTENT SIZE AND CONTENT PARSING"""
            if len(self.request) < offset + self.MESSAGE_CONTENT_SIZE.value:
                raise ValueError("Message is too short to be valid. No valid  content size field was received.")
            self.content_size = struct.unpack('<I', self.request[
                                                   offset : offset + self.MESSAGE_CONTENT_SIZE.value])
            offset = offset + self.MESSAGE_CONTENT_SIZE.value

            if len(self.request) < offset + self.content_size:
                raise ValueError("Message is too short to be valid. No valid content field was received.")


        except struct.error as e:
            print(f"Error unpacking message payload: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def symmetrical_key_request_message(self, offset):
        """ Handle symmetrical key request messages """
        # Make sure that Content Size = 0
        self.content_size = struct.unpack('<I', self.request[
                                            offset: offset + self.MESSAGE_CONTENT_SIZE.value])
        if self.content_size != 0:
            raise ValueError("Invalid message. Symmetrical key request message must be empty.")


    def symmetrical_key_send_message(self, offset):
        """ Handle symmetrical key send messages """
        if len(self.request) < offset + self.MESSAGE_CONTENT_SIZE.value:
            raise ValueError("Message is too short to be valid. No valid  content size field was received.")
        self.content_size = struct.unpack('<I', self.request[
                                                offset: offset + self.MESSAGE_CONTENT_SIZE.value])
        offset = offset + self.MESSAGE_CONTENT_SIZE.value
        self.message_content = struct.unpack('<16s', self.request[offset: offset + EncryptionKeysSizes.SYMMETRIC_KEY_SIZE.value])
        #todo maybe it's like the text_send_message? just interpret as bytes???

        #TODO add a check to make sure that the sizes are correct and matching (content size = len(message content) and that it's correct).
    def text_send_message(self, offset):
        if len(self.request) < offset + self.MESSAGE_CONTENT_SIZE.value:
            raise ValueError("Message is too short to be valid. No valid  content size field was received.")
        self.content_size = struct.unpack('<I', self.request[
                                                offset: offset + self.MESSAGE_CONTENT_SIZE.value])

        offset = offset + self.MESSAGE_CONTENT_SIZE
        self.message_content = self.request[offset: offset + self.content_size[0]]

        #todo same as above, validate length matching and correct type etc...


class Request:
    def __init__(self, request_bytes):
        self.request = request_bytes
        self.client_id = None
        self.client_version = None
        self.request_code = None
        self.offset = 0
        self.payload_size = None

        self.parse_basic_request_details()  # Initializing all of the fields above.

        """different payload fields, depending on the request (601 and 604 are empty):"""
        if self.request_code == RequestType.REGISTER_REQUEST.value:  # case 600
            self.client_name = None
            self.public_key = None
        elif self.request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:  # case 602
            self.target_client_id = None
        elif self.request_code == RequestType.SEND_MESSAGE_REQUEST.value:  # case 603
            self.message = None

        self.parse_payload()


    def parse_payload(self):
        try:
            if len(self.request) < self.offset + RequestOffset.REQUEST_PAYLOAD_SIZE.value:
                raise ValueError("Request is too short to be valid. No valid payload size field was received.")

            self.payload_size = struct.unpack('<I', self.request[self.offset:self.offset + RequestOffset.REQUEST_PAYLOAD_SIZE.value])
            self.offset = self.offset + RequestOffset.REQUEST_PAYLOAD_SIZE.value

            # Parse the payload according to the different request types
            if self.request_code == RequestType.CLIENT_LIST_REQUEST.value or self.request_code == RequestType.RECEIVE_INCOMING_MESSAGES_REQUEST.value:
                ###TODO do I need to ignore the payload size and payload fields? or parse them and validate that it's actually 0??
            elif self.request_code == RequestType.REGISTER_REQUEST.value:
                if len(self.request) < self.offset + RequestFieldsSizes.CLIENT_NAME_SIZE.value:
                    raise ValueError("Request is too short to be valid. No valid client name field was received.")
                client_name_bytes = struct.unpack('<255s', self.request[self.offset:self.offset + RequestFieldsSizes.CLIENT_NAME_SIZE.value])
                self.client_name = client_name_bytes.split(b'\x00', 1)[0].decode('ascii')
                self.offset = self.offset + RequestFieldsSizes.CLIENT_NAME_SIZE.value

                if len(self.request) < self.offset + RequestFieldsSizes.PUBLIC_KEY_SIZE.value:
                    raise ValueError("Request is too short to be valid. No valid public key field was received.")
                public_key_bytes = struct.unpack('<160s', self.request[self.offset:self.offset + RequestFieldsSizes.PUBLIC_KEY_SIZE.value])
                self.public_key = public_key_bytes[0]

                # TODO register the user and/ or call the other functions

            elif self.request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:
                if len(self.request) < self.offset + RequestFieldsSizes.CLIENT_ID_SIZE.value:
                    raise ValueError("Request is too short to be valid. No valid client id field was received.")
                client_id_bytes = struct.unpack('<16s', self.request[self.offset:self.offset + RequestFieldsSizes.CLIENT_ID_SIZE.value])
                self.target_client_id = client_id_bytes[0]

                # TODO call the next functions!

            elif self.request_code == RequestType.SEND_MESSAGE_REQUEST.value:
                self.message = Message(self.request[self.offset:self.offset + self.payload_size[0]])

            else:
                raise ValueError("Invalid request code.")



        except struct.error as e:
            print(f"Error unpacking request payload: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def parse_basic_request_details(self):
        """Parses the request that came from the client and calls the appropriate functions"""
        try:
            # The minimum size of a request is 16 bytes (for the client id field)
            if len(self.request) < RequestOffset.MIN_REQUEST_SIZE.value:
                raise ValueError("Request is too short to be valid. No valid Client ID was received.")

            self.offset = RequestOffset.MIN_REQUEST_SIZE.value

            # Unpack the request id
            self.client_id = struct.unpack('<16s', self.request[:self.offset])

            # validate_range("version", server_version, "uint8_t") TODO add this!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            # self.validate_status(status)

            if len(self.request) < self.offset + RequestOffset.CLIENT_VERSION_SIZE.value:
                # Check that we received a valid client version
                raise ValueError(
                    "Request is too short to be valid, invalid ToClient ID length was received.")

            # gather the client version
            self.client_version = struct.unpack('<B', self.request[self.offset:self.offset + RequestOffset.CLIENT_VERSION_SIZE.value])
            self.offset += RequestOffset.CLIENT_VERSION_SIZE.value

            if len(self.request) < self.offset + RequestOffset.REQUEST_CODE_SIZE.value:
                # Check that we received a valid request code field
                raise ValueError(
                    "Request is too short to be valid, invalid request code length was received.")

            # gather the request code
            self.request_code = struct.unpack(
                '<H', self.request[self.offset:self.offset + RequestOffset.REQUEST_CODE_SIZE.value])
            self.offset += RequestOffset.REQUEST_CODE_SIZE.value

            #TODO add length validation for all "size" fields followed by payload, like in the next example:
            """
            # Skip the filename of `name_len` bytes
            filename_received = response[offset:offset + name_len].decode('ascii')
            offset += name_len

            # validating the filename's length, in comparison to the filename length field.
            if len(filename_received) != name_len:
                raise ValueError(
                    f"Received filename's length is:({len(filename_received)}), does not match name_len ({name_len}) field.")

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

#TODO add a validate username function!!!!!!!!!!!!!
class Database:
    DB_FILENAME = "defensive.db"
    CLIENTS_TABLE_NAME = "clients"
    MESSAGES_TABLE_NAME = "messages"

    def __init__(self):
        self.connection = sqlite3.connect(self.DB_FILENAME)
        self.create_tables() # Creates the clients and messages tables if they don't exist


    def does_client_exist(self, username: str) -> bool:
        """Checks if the username exists in the database"""
        cursor = self.connection.cursor()
        try:
            # Query to check if the username exists
            cursor.execute(
                f"SELECT COUNT(*) FROM {self.CLIENTS_TABLE_NAME} WHERE name = (?);", username)
            result = cursor.fetchone()
            return result[0] > 0  # True if count > 0, otherwise False
        except Exception as e:
            return False
        finally:
            cursor.close()

    def get_client_by_name(self, username: str):
        """Get a client by their username."""
        cursor = self.connection.cursor()
        try:
            self.validate_username(username) # Validate the given username
            cursor.execute(
                f"SELECT * FROM {self.CLIENTS_TABLE} WHERE name = ?;", (username,)
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
            self.validate_username(username)

            # Ensure the client doesn't already exist
            if self.does_client_exist(username):
                raise ValueError(f"Client '{username}' already exists in the database.")

            # Generate a server-side client ID TODO maybe it's just an index? and not a random uuid????????
            server_client_id = os.urandom(RequestFieldsSizes.CLIENT_ID_SIZE.value)

            # Insert the client into the database
            cursor.execute(
                f"INSERT INTO {self.CLIENTS_TABLE_NAME} (id, name, public_key, last_seen) VALUES (?, ?, ?, ?);",
                (server_client_id, username, bytes(RequestFieldsSizes.PUBLIC_KEY_SIZE.value),
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
            cursor.execute(f"SELECT name FROM {self.CLIENTS_TABLE_NAME} WHERE name != ?;", username)
            return [row[0] for row in cursor.fetchall()]
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

    def validate_username(self, username: str):
        if len(username) > RequestFieldsSizes.CLIENT_NAME_SIZE.value:
            raise ValueError("Invalid username. The username must not exceed 255 characters.")
        for ch in username:
            if not ch.isalpha() and ch != " ":
                raise ValueError("Invalid username. The username must not contain any special characters.")

    def get_username_by_uuid(self, client_id: bytes) -> str:
        """
        Get a client's username by their UUID (id).
        Returns the username as a string or None if the client does not exist.
        """
        cursor = self.connection.cursor()
        try:
            # Query the database for the username
            cursor.execute(
                f"SELECT name FROM {self.CLIENTS_TABLE_NAME} WHERE id = ?;", (client_id,)
            )
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
                f"SELECT from_client, content FROM {self.MESSAGES_TABLE_NAME} WHERE to_client = ?;", (to_client_id,)
            )
            results = cursor.fetchall()

            # Process each message
            for from_client_id, content in results:
                username = self.get_username_by_uuid(from_client_id)  # Get the username from the from_client ID
                if username is not None:
                    messages.append([username, content])

            # Delete the messages after fetching
            self.delete_messages_by_to_client(to_client_id)
        except Exception as e:
            print(f"ERROR: Failed to fetch messages for to_client ID '{to_client_id}': {e}")
        finally:
            cursor.close()  # Ensure the cursor is closed

        return messages

    def delete_messages_by_to_client(self, to_client_id: bytes) -> None:
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
                        id BLOB PRIMARY KEY,
                        name TEXT,
                        public_key BLOB,
                        last_seen DATETIME
                    )"""
            )
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS {self.MESSAGES_TABLE_NAME}(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        to_client BLOB, 
                        from_client BLOB,
                        type INTEGER,
                        content BLOB
                    )"""
            )
            print("Tables created successfully.")
        except Exception as e:
            print(f"ERROR: Failed to create tables: {e}")
        finally:
            cursor.close()  # Ensure the cursor is closed



class ClientManager:

    BUFFER_SIZE = 4096

    def __init__(self, socket, database):
        self.socket = socket
        self.request = None
        self.buffer = b""
        self.db = database
        self.client_id = None
        self.username = None
        self.last_active_time = None
        self.receive_and_process_request()

    def receive_and_process_request(self):
        """
        Receive data from the socket and process it into a Request object.
        """
        try:
            while True:
                # Receive data from the socket
                chunk = self.socket.recv(self.BUFFER_SIZE)
                if not chunk:
                    # Client disconnected
                    print("Client disconnected.")
                    return False

                # Accumulate the chunk into the buffer
                self.buffer += chunk

                # Create and parse the Request object
                self.request = Request(self.buffer)
                self.client_id = self.request.client_id
                self.username = self.request.client_name
                #self.last_active_time = self.request.last_seen
                print(f"Processed request: {self.request}")
                self.buffer = b""  # Clear the buffer for the next request
                return
        except socket.error as e:
            print(f"Socket error: {e}")
            return


    def handle_request(self):
        request_code = self.request.request_code

        try:

            self.db.update_last_seen(self.username) # Update the last seen time, because the user sent a request.

            #TODO after handling the request, handle the response and return it!!!
            if request_code == RequestType.CLIENT_LIST_REQUEST.value:
                self.client_list_request()
            elif request_code == RequestType.RECEIVE_INCOMING_MESSAGES_REQUEST.value:
                self.incoming_messages_request()
            elif request_code == RequestType.REGISTER_REQUEST.value:
                self.register_request()
            elif request_code == RequestType.PUBLIC_KEY_OF_OTHER_CLIENT_REQUEST.value:
                self.public_key_other_client_request()
            elif request_code == RequestType.SEND_MESSAGE_REQUEST.value():
                self.send_message_request()
        except Exception as e:
            print(f"Request error: {e}")
            #TODO add the exception as to just return a server error maybe?
        finally:
            self.db.update_last_seen(self.username) #todo maybe it's not here??? maybe it's better in the top of the function????


    #TODO update the request handling functions
    def client_list_request(self):
        client_list = self.db.fetch_all_registered_clients(self.username)
        # TODO continue from here, need to send it back I GUESS
    def incoming_messages_request(self):
        messages_list = self.db.fetch_all_registered_messages(self.username)
        # todo continue with the response etc..

    def register_request(self):
        #continue with the logic of registering a new user, and check for a current user already...
        if not self.db.does_client_exist(self.username):
            server_client_id = self.db.insert_client(self.username, self.request.public_key)
        else:
            raise ValueError(f"Username '{self.username}' already exists in the DB.")


    def public_key_other_client_request(self):
        public_key_other_client = self.db.get_public_key_by_id(self.request.target_client_id)


    def send_message_request(self):
        from_client_id = self.client_id
        target_client_id = self.request.message.target_client_id
        message_type = self.request.message.message_type
        message_content = self.request.message.message_content

        self.db.insert_message(target_client_id, from_client_id, message_type, message_content)



class Server:
    """
    A modular server class that handles multiple client connections using selectors.
    Includes:
    - Non-blocking socket handling
    - Client message handled by ClientManager
    """

    MAX_CONNECTIONS = 100

    # port number constants:
    MIN_PORT_NUMBER = 0
    MAX_PORT_NUMBER = 65535
    DEFAULT_PORT_NUMBER = 1357
    PORT_FILE_NAME = "myport.info"

    IP_ADDRESS = '127.0.0.1'

    def __init__(self):
        self.host = self.IP_ADDRESS
        self.port = self.read_port()
        self.sel = selectors.DefaultSelector()
        self.running = True
        self.db = Database()  # Replace with your actual DB manager
        self.sock = None

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
        self.sock.bind((self.host, self.port))
        self.sock.listen(Server.MAX_CONNECTIONS)
        self.sock.setblocking(False)
        self.sel.register(self.sock, selectors.EVENT_READ, self._accept_client)
        print(f"Server is running on {self.host}:{self.port}")

    def _accept_client(self, sock: socket.socket) -> None:
        """Handles new client connections."""
        try:
            conn, addr = sock.accept()
            conn.setblocking(False)
            print(f"New connection from {addr}")

            # Create a ClientManager for this connection
            client = ClientManager(conn, self.db)

            # Register the client socket with the selector for reading
            self.sel.register(conn, selectors.EVENT_READ, client.handle_request())
        except Exception as e:
            print(f"ERROR: Failed to accept a client: {e}")

    def run(self) -> None:
        """Runs the server and processes events using the selector."""
        self._create_socket()
        try:
            while self.running:
                events = self.sel.select(timeout=None)  # Wait for events
                for key, _ in events:
                    callback = key.data  # The registered function (e.g., _accept_client or handle_message)
                    callback(key.fileobj)  # Call the registered function
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
        self.sel.close()
        if self.sock is not None:
            self.sock.close()

def main():
    """The main function, creating the user_id for the runtime requests sequence, parsing the info_files and then calls the script."""
    server = Server()
    server.run()


if __name__ == "__main__":
    main()
