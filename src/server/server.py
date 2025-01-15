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
from enum import Enum

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
            self.target_client_id = None
            self.message_type = None
            self.content_size = None
            self.message_content = None

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
                #TODO call the parse message request function!
            
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

            # validate_range("version", server_version, "uint8_t")
            # self.validate_status(status)

            """
            # Check if the status indicates an error (1001, 1002, 1003)
            if status in (
            Status.FILE_NOT_FOUND_ERR.value, Status.NO_FILES_IN_USER_FOLDER_ERR.value, Status.SERVER_ERROR.value):
                if status == Status.FILE_NOT_FOUND_ERR.value:
                    print(
                        f"Error received with status: {status}, file doesn't exist on server, operation {request_operation} failed.")
                elif status == Status.NO_FILES_IN_USER_FOLDER_ERR.value:
                    print(
                        f"Error received with status: {status}, there are no files in the user folder in the server, operation {request_operation} failed.")
                else:
                    if server_version != CLIENT_VERSION:  # if a general error is returned, and there's a version mismatch between client and server, print it.
                        print(
                            f"Error received with status: {status}, version mismatch between server and client, operation {request_operation} failed.")
                    else:
                        print(
                            f"Error received with status: {status}, general server error, operation {request_operation} failed.")
                print()  # print a new line
                return
            """

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

            """
            if len(self.request) < offset + MessageOffset.TYPE_MESSAGE_SIZE.value:
                # Check that we received a valid type field
                raise ValueError(
                    "Response is too short to be valid, invalid request type length was received.")

            request_type = struct.unpack('<B', self.request[offset:MessageOffset.TYPE_MESSAGE_SIZE.value])
            offset += MessageOffset.TYPE_MESSAGE_SIZE.value
            """
            # TODO add a request type managing!!

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
                    if chunk:
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
