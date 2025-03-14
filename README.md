# MessageU - Encrypted Message Transmission System
# 📃Table of Contents📃
- [Introduction](#introduction)
- [Server](#server-python)
- [Client](#client-c)
- [Defensive Checks & Error Handling](#defensive-checks--error-handling)
- [Communication Protocol](#communication-protocol)
- [Encryption](#encryption)
- [Author](#author)
# Introduction
## This project was developed in C++ and Python, as a final project for the "Defensive Systems Programming - 20937" 2025A course, part of the Computer Science degree at the Open University of Israel.
 This project implements a secure encrypted message transmission system with a client-server architecture. Messages are encrypted before transmission to protect sensitive data from interception.
 - Client: Written in C++, sends requests to the server. Some of the requests are messages to another client.
 - Server: Written in Python, receives requests from the client, processes them, and forwards messages to another client when requested.
 - End-to-End Encryption: Ensures that only authorized recipients can decrypt messages (text messages or files).
# Server (Python)
## General Information
 - The server is a stateless server. Each request is handled individually, with no request relying on data from an earlier session data between requests.
 - The server is multi-client, by using selector module, and is non-blocking.
 - The server's version is 2, and it's working with an SQLite 3 database to store clients and messages
## Server Requirements
 - Python 3.12 and above is required
 - No third-party libraries beyond Python’s standard library (e.g., socket, struct, selector).
## Server Files
### 1. server.py - contains:
  - main() function - calls the __init__ of a Server class, and then runs it.
  - Server class - creates a Server instance, reads the port number from the myport.info file (optional, defaults to 1357 if n\a) and then starts a non-blocking, selector driven server, and waits for user connections.
  - ClientManager class - creates an instance of a client, which receives the client request using the socket, parses it using the Request and Message class, and then sending a response back using the Response class.
  - Request class - parses the incoming request, and validates that it has exact, expected data.
  - Message class - a subset of the Request class, parses the incoming request of type message.
  - Response class - generates a response and sends it back to the user.
  - Database class - Created on the first run of the server, and holds 2 tables - Clients and Messages. The clients table holds all of the registered clients and their required information. The messages table holds the messages sent between clients, and they're deleted once they've been sent to the other client.
### 2. myport.info:
  - Contains the port number for use in the Server class initialization. If invalid / doesn't exist - the server will default to port 1357.
## Running The Server
 1. Optional: Create a virtual environment (recommended, but not required).
    - python3 -m venv venv
    - source venv/bin/activate  (Linux/Mac)
    - .\venv\Scripts\activate   (Windows)
 2. Place the myport.info file, which only contains a valid port number in the same folder as server.py
 3. Start the server
 4. The server will begin listening on the port read from myport.info, and it's assigned IP address (defined in the code) for new connections

# Client (C++)
## General Information
  - The client has a text-based GUI for the user to interact with the server, and to send messages to other clients.
  - The client supports end to end encryption using AES key (which is encrypted in itself with RSA encryption).
  - The client supports encrypted text message and file transmission (up to almost 4GB for each message sent).
  - The client's version is 2, since it supports file transmission.
  - The client contains a main loop to accept information and requests from the user.
  - The client will stop the user from not following the protocol, and will require him to make certain requests before others.
## Client requirements
  - C++17 is required for the client program
  - Crypto++ version 8.80 and earlier
  - Boost version 1.87
  - Compiling on Windows with Visual Studio Community 2022 (or 2019)
## Client Files
### 1. client.cpp functions:
  - main() function - initializes a serverConnection instance, and then runs an infinite loop that asks the user for input (different requests for the server or exiting). It enforces numerical user input, and then calls handleUserInput function.
  - handleUserInput() function - takes the input operation code as a parameter, and calls the different handle request function (there's one for each type of request). The user will not be able to call any request other then to register if he's not registered, and will not be able to call any request after registering if there are 0 clients on memory (and he will need to call the clients list request first). It also rejects any unknown user input code (and restarts the loop).
  - handleClientRegister() function - Checks if there's a me.info file already. If there is, cancel operation. if there's not - ask the user for a username input, validate it, create a private and public key, send a register request to the server, and if the response is successful -> calling CreateClientInfoFile() which creates the new me.info file for this client/
  - handleClientsListAndFetchMessagesRequest() - sends a request for either a clients list request, or a waiting messages request, and call the parseResponse function to print the response data.
  - handlePublicKeyRequest() - asks for a client name, checks if he is in the clients list (based in the Singelton class of ClientHandler). If he is - request for his public key from the server, call the response function, which handles the public key updating for the client.
  - handleMessageSend() - handles the logic for the 4 types of message sending. input the client name the user wants to send a message to and then do one of the following:
    - Symmetric Key Request message - send a request with this type of message to the client through the server.
    - Send Symmetric Key Request Message - Checks if the target user already asked our user for a symmetric key (if not, he can't send it since it's a vulnerability). Then checks if the user already has a symmetric key shared with this client, if not it checks if the user has the public key of this client (warning the user for each of those checks and not letting him go on with the request). If everything is valid - create a symmetric key, save it for this client in the clients list, encrypt it using the target client's public key, and send it using the request message.
    - Send Text Message - checks if the user has a symmetric key with a client. If he does - let him input a text message, check that it fits in the maximum size and if not truncates it. Then- encrypts it with the symmetric key, and sends it to the client.
    - Send File Message - checks if the user has a symmetric key with a client. If he does - let him input a full path to the file he wants to send (non-ASCII path only), checks that the file exists and has data, reads it into a vector, encrypts it using the symmetric key and sends it to the target client. Because of limitations of vector and ram usage in CPP, the maximum file size will be almost 4GB, but it won't let the user send above 2GB of file size. It works for all file types otherwise, and it is a known limitation, that it's solution is outside the scope of this project. 
  - parseResponse() - parses the response from the server and takes care of processing the rest (I've decided to leave it all in one function, since the functionality of response processing is very small ,and inconsistent between the different response types). First, it parses the request header and validates it. then it handles all of the different response types:
   - Register response - takes the client ID (16 byte UUID) the server created for the user, and passes it on (the register request function inserts it into the me.info file).
   - Client list response - checks if there are any other clients, and prints them all (numbered), and inserts each one into our ClientHandler clients list. If there are 0 clients, it notifies the user about it.
   - Public Key response - reads the public key of another client and insert it into the clientHandler Singelton instance (our on-memory clients list).
   - Message Sent response - reads the client id and message id.
   - Fetching incoming messages response - checks if there are any messages for you, if not - notify the user and return. if there are, in a loop (while payload size > 0): parse the message header, get the client name from the client ID returned (if there isn't any - write From: Unidentified client). then for each type of message fetched:
     - symmetric key request - If the client is unkown - notify the user that an unknown client asked him for a symmetric key. Otherwise, print the some other client asked for a symmetric key, and update the clients list such that this client asked for a symmetric key (boolean field) - so the user will be able to send him a symmetric key.
     - symmetric key send - receive the encrypted symmetric key, decrypt it using the client's private key (fetched from the me.info file), and then save it in the clients list for this specific client.
     - text message send - validate the size received, decrypt the message using the shared symmetric key with the other client, and print it to the user to see.
     - file send message - validate the size, receive the file bytes, decrypt them, create a random 16-32 character file name, and save it WITHOUT extension in the %TMP% folder in windows. Print the new file path.
   - Error response - If there is ANY problem with the server logic, it sends back an error response, to let the user know there was some error.
  - Many other functions () - Throughout the file, there are MANY other utility functions, for the me.info file creation, validation, and fetching data from there. For string/text validation, conversion of client ID to the required format for the me.info file and vice versa, creating a random file name, etc...
  - Wrapper functions for the cryptoPP library, provided by the course staff.
### 2. Client.cpp Classes:
 - BaseRequest class - contains the request attributes, and has MANY inheriting classes (including message classes) that are all responsible for creating a request with the correct attributes, and sending it to the server (there's a different send() function for each request class).
 - BaseResponse class - contains the response attributes, with many inheriting classes. Responsible for organizing the responses after they're fetched and parsed.
 - ClientInfo struct - Contains a client name, public key, symmetric key and a boolean symmetric_key_requested field, for use with the ClientHandler Singleton class.
 - ClientHandler Singleton Class - Has ONE instance used throughout the program, and contains an unordered map of {client ID : ClientInfo struct}. It holds all of the relevant clients' data on memory in during runtime. It contains many functions to add client, get the singleton instance, set the attributes, get the number of clients, and fetch a specific client etc.
 - ServerConnectionManager class - contains ip, port, io_context and a socket shared_ptr. The constructor reads the server.info file and validates it, and grabs the ip and port. Then, there's a connectToServer() function which of course - creates a socket with the server and returns it.
 - Wrapper classes for the cryptoPP library, provided by the course staff.
### 3. Client.hpp:
 - Contains many constants (inside ProtocolConstants namespace) and includes in the top of the file.
 - Contains all of the function and class declarations
### 4. server.info:
 - Contains the IP and PORT of the server, in the current format: 127.0.0.1:1234 . MUST be included in the project directory.
### 5. me.info:
 - Contains the client name in the first row, the client ID hexadecimal form (32 hex chars) in second row, and in 3rd row onwards - the base64-encoded private key of the client.
## Compiling and Running the Client:
 1. Create a Visual Studio project (recommended) or use a CMake-based workflow.
 2. Install the required libraries above, and add them to the project.
 3. Add the .cpp, .hpp and server.info file to the project directory.
 4. Build in Debug mode - x86 / win32 configuration. (REQUIRED!)
 5. Run it / launch the .exe file.
## Client Menu Loop and Operation:
### Below is a brief summary of each input code option:
#### 1. (110) Register
   - Prompts the user for a new username (unless the user already has me.info, in which case it returns and notified the user he's already registered).
   - Sends a “Registration” request (code 600) to the server with the username and the public key.
   - If successful, the server returns a unique Client ID (UUID) that the clients stores in me.info file, with the client name and private key(base 64).
#### 2. (120) Request for clients list
   - Sends a “Clients list” request (601) to the server.
   - Prints all the other registered clients (client ID and name).
#### 3. (130) Request for public key
   - Prompts for the target user’s name, checks that the user has it in his runtime clients list (ClientHandler class).
   - Sends a request code 602 to the server.
   - Receives the public key of that user (code 2102 in response).
   - Store the target user’s public key in memory (clients list).
#### 4. (140) Request for waiting messages
   - Sends a 604 request (fetch all messages waiting for the user).
   - The server’s response (code 2104) may contain multiple messages. For each message:
     - If it’s a “request for symmetric key” (type 1), display Request for symmetric key.
     - If it’s a “send your symmetric key” (type 2), it contains the other party’s symmetric key encrypted with your public key. Decrypt with your private key and store that new symmetric key in memory.
     - If it’s a “text message” (type 3), decrypt it with the appropriate symmetric key you have stored for that user. If you don’t have it or it fails, display can't decrypt message.
     - If it’s a “file” (type 4), decrypt it with the existing symmetric key and save to a temporary file with a random file name in your system’s %TMP% folder. Print where it was saved.
#### 5. (150) Send a text message
   - Prompts for a target username.
   - Check that you already have a symmetric key shared with this user, if not - notify the user and return.
   - Prompts for the message text.
   - Encrypts that text with the symmetric key you share with that user (type 3 message).
   - Sends request 603 to the server.
#### 6. (151) Send a request for symmetric key
   - Prompts for a target username.
   - Creates a type 1 message (“Request for symmetric key”), which is always empty content.
   - Sends it to the server.
#### 7. (152) Send your symmetric key
   - Prompts for a target username.
   - Checks that the target user already asked the sending user a request for symmetric key using the clients list on memory. If not - notify the user that he can send a request for it himself and return.
   - If there's already a symmetric key - return. if not - generates a new symmetric key.
   - Encrypts that symmetric key with the target user’s public key (RSA) into a type 2 message. If there isn't the target's public key, notifies the user he must ask for the public key and returns.
   - Sends it to the server.
#### 8. (153) Send a file 
   - Prompts for a target username.
   - Checks for the same conditions as text message - 150.
   - Prompts for a filename/path, ensures it is ascii only and a valid- nonempty file.
   - Reads the file content.
   - Encrypts with the symmetric key you share with that user and sends as a type 4 message.
#### 9. (0) Exit client
   - Client gracefully closes and frees resources.

# Defensive Checks & Error Handling
### - The client & server modules are using extensive error handling logic, with try, catch and throw (or try, except and raise for the Server). There are detailed error messages and a specific stack trace for different errors in different locations. 
## Client
 - The client module is validating string lengths, null termination, proper sizes, protocol structure (before sending and while parsing a response). It ensures that the user follows the protocol EXACTLY like he should ("Never trust the user"). It also validates the me.info file to make sure it wasn't compromised (basic tests). It ensures there are the correct keys before encrypting/decrypting - and throws the correct error if there isn't.
 - If there's an error in the first part in the logic of the Client (when reading the IP and PORT)- it exits the program. Else - it restarts the menu loop.
## Server
 - The server module is also validating string lengths, null termination, proper sizes, protocol structure (before responding and while parsing a client request). It ensures everything runs like the protocol states.
 - If there's an error in the first part in the logic of the Server (when reading the port and initializing the server) - it exits the server. Else - it responds with a general error 9000.

# Communication Protocol
 1. The protocol is binary over TCP. Both requests and responses have a header and an optional payload.
 2. The protocol is little-endian. Both the Client and Server modules make sure to convert to - and from little endian, if the computer architecture that runs them is big-endian.
 3. The protcol structure is available in the official course book.

# Encryption
 - Asymmetric: RSA-1024.
 - Symmetric: AES-CBC with a 128-bit key.
   - The IV can be assumed zeroed for this exercise.
 - Uses Crypto++ with course-provided wrappers to handle both RSA and AES encryption and decryption.
 - Public keys are 160 bytes in the protocol, typically including any required header data (like X.509 structures).
 - Private keys are 128 bytes in the protocol, and are encoded and decoded to and from base64 for storage.
 - Symmetric keys are 16 bytes in the protocol, and are transferred from client A to client B after encrypting them with the public key of client B.

# Author
Omri Peretz, student at the Open University of Israel
