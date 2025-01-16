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
VERSION_NUMBER = 1
IP_ADDRESS = '127.0.0.1'

# port number constants:
MIN_PORT_NUMBER = 0
MAX_PORT_NUMBER = 65535
PORT_FILE_NAME = "myport.info"


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


class Client:
    def __init__(self):
        self.id = None  # 16 bytes ID (128 bits)
        self.user_name = None  # 255 bytes ASCII null-terminated string
        self.public_key = None  # 160 bytes public client key
        self.last_seen = None  # date, hour format - where the client last sent a request to the server


class Message:
    def __init__(self):
        self.id = None  # 4 bytes index for the message ID
        self.to_client = None  # 16 bytes ID of the target client
        self.from_client = None  # 16 bytes ID of the sender client
        self.type = None  # 1 byte of the type of message
        self.content = None  # the message payload


class MessageParser:
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
                #handle this, make sure that the content size = 0 and dump the payload
            elif self.message_type == self.SYMMETRICAL_KEY_SEND_MESSAGE.value:
                #handle that, take the symmetrical key and do something with it
            elif self.message_type == self.TEXT_SEND_MESSAGE.value:
                #hanlde thatt, take the encrypted message content
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



class Request:
    def __init__(self, request_binary):
        self.request = request_binary
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
                self.client_id = client_id_bytes[0]

                # TODO call the next functions!

            elif self.request_code == RequestType.SEND_MESSAGE_REQUEST.value:
                self.message = MessageParser(self.request[self.offset:self.offset + self.payload_size])

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

        try:
            cursor = self.conn.cursor()
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


    def insert_client(self, username: str):
        """Insert a new client into the DB"""
        if not self.does_client_exist(username):
            client_id = os.urandom(RequestFieldsSizes.CLIENT_ID_SIZE.value)
            cursor = self.connection.cursor()
            try:
                cursor.execute(
                    f"INSERT INTO {self.CLIENTS_TABLE_NAME} (id, name, public_key, last_seen) VALUES (?, ?, ?, ?);",
                    (client_id, username, bytes(RequestFieldsSizes.PUBLIC_KEY_SIZE.value), datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
                self.connection.commit()
            except Exception as e:
                print(f"Error inserting new client into DB: {e}")
            finally:
                cursor.close()
        else:
            print(f"Client {username} already exists in the DB") #TODO maybe throw an error here??

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
                        id INTEGER,
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
    def __init__(self, request_bytes, database):
        self.request_bytes = request_bytes
        self.request = Request(self.request_bytes)
        self.db = database
        self.client_id = self.request.client_id
        self.username = None
        self.last_active_time = None

    def handle_request(self):
        request_code = self.request.request_code

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


    #TODO update the request handling functions
    def client_list_request(self):
        #continue.......
    def incoming_messages_request(self):
        #continue...

    def register_request(self):
        #continue with the logic of registering a new user, and check for a current user already...


    def public_key_other_client_request(self):



    def send_message_request(self):
        target_client_id = self.request.message.target_client_id
        message_type = self.request.message.message_type
        message_content_size = self.request.message.content_size
        message_content = self.request.message.message_content

        #continue with the logic to send the message......

    def get_current_timestamp(self) -> str:
        """Returns the current time in ISO 8601 format, for use in DB clients table"""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # ISO 8601 format


class PortFileProcessor:
    """
    A class to validate and process the .info files that the client uses to communicate with the server.
    """

    DEFAULT_PORT_NUMBER = 1357

    def __init__(self, port_file_name=PORT_FILE_NAME):
        self.port_file_name = port_file_name  # "myport.info"
        self.port = None

    def read_file(self, filename) -> str:
        """Reads a file and returns its content."""
        try:
            with open(filename, "r") as file:
                data = file.read()
            return data
        except FileNotFoundError:
            print(f"WARNING: File '{filename}' not found.")
        except Exception as e:
            print(f"WARNING: Failed to read '{filename}': {e}")
        return None

    def is_valid_port(self, port: int) -> bool:
        """Checks if the port number is within the valid range."""
        return MIN_PORT_NUMBER <= port <= MAX_PORT_NUMBER

    def process_port_file(self) -> int:
        """
        Checks if the file exists and is valid. If valid, returns the port number.
        Otherwise, returns the default port number and prints a warning.
        """
        port_file_data = self.read_file(self.port_file_name)
        if port_file_data:
            try:
                port = int(port_file_data.strip())
                if self.is_valid_port(port):
                    self.port = port
                    return self.port
                else:
                    print(f"WARNING: Port number in '{self.port_file_name}' is not valid: {port}")
            except ValueError:
                print(f"WARNING: File '{self.port_file_name}' contains invalid data")
        else:
            print(f"WARNING: Unable to process '{self.port_file_name}'")

        # Fallback to default port
        self.port = self.DEFAULT_PORT_NUMBER
        print(f"Returning default port number: {self.port}")
        return self.port


def selector_server(port_number):
    """Starts a non-blocking TCP server using selectors."""
    sel = selectors.DefaultSelector()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((IP_ADDRESS, port_number))
    server_socket.listen(5)  # TODO add a constant + how much clients do I need to accept at once?
    server_socket.setblocking(False)  # Non-blocking mode
    sel.register(server_socket, selectors.EVENT_READ, data=None)

    db = Database()

    print(f"Server running on port {port_number}...")

    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                # Handle new connections
                client_socket, client_address = key.fileobj.accept()
                print(f"New connection from {client_address}")
                client_socket.setblocking(False)
                sel.register(client_socket, selectors.EVENT_READ, data=client_address)
            else:
                # Handle client messages
                client_socket = key.fileobj
                client_address = key.data
                try:
                    # Create a buffer to store received data for this client
                    if not hasattr(client_socket, "buffer"):
                        client_socket.buffer = b""

                    chunk = client_socket.recv(4096)  # Read a chunk of data TODO add a constant
                    if chunk: #TODO is it while or if?????????????????????????????????????????????????????
                        client_socket.buffer += chunk  # Accumulate data
                        print(
                            f"Accumulating data from {client_address}: {len(client_socket.buffer)} bytes received so far.")
                    else:
                        # Connection closed by the client; process the complete data
                        print(f"Connection closed by {client_address}.")
                        print(f"Full message from {client_address}: {client_socket.buffer.decode('utf-8')}")

                        # Send a response
                        response = "ACK: Server received your complete message."
                        client_socket.send(response.encode('utf-8'))

                        # Clean up
                        sel.unregister(client_socket)
                        client_socket.close()
                except Exception as e:
                    print(f"Error handling client {client_address}: {e}")
                    sel.unregister(client_socket)
                    client_socket.close()


def main():
    """The main function, creating the user_id for the runtime requests sequence, parsing the info_files and then calls the script."""
    port_file = PortFileProcessor(PORT_FILE_NAME)
    port_number = port_file.process_port_file()  # process the port file and validate it, assign the required port number.

    selector_server(port_number)


if __name__ == "__main__":
    main()
