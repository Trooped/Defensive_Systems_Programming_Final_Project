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
#import statements
import socket
import selectors

#general constants:
VERSION_NUMBER = 1
IP_ADDRESS = '127.0.0.1'

#port number constants:
MIN_PORT_NUMBER = 0
MAX_PORT_NUMBER = 65535
PORT_FILE_NAME = "myport.info"



class PortFileProcessor:
    """
    A class to validate and process the .info files that the client uses to communicate with the server.
    """

    DEFAULT_PORT_NUMBER = 1357

    def __init__(self, port_file_name = PORT_FILE_NAME):
        self.port_file_name = port_file_name #"myport.info"
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
    server_socket.listen(5) #TODO add a constant + how much clients do I need to accept at once?
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