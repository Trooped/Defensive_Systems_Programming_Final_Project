/**
@File: client.hpp
@Author: Omri Peretz
@Date: March 2025
@Assignment: Maman 15
@Course: Defensive Systems Programming

@Description:
This file is a client program (.h file) written in C++, that communicates with a server program. Used for a message transfer protocol between different clients.
The client and server communicate over TCP, with a compatible, agreed upon protocol. The data is being sent in little endian format.
The text & files being sent are encrypted and decrypted using a 16 byte symmetric key (AES - CBC). The symmetric key is encrypted and sent using RSA.
The symmetric key transferred between clients in the following mechanism:
0. Client A and Client B register to the server, and create a private and public key.
1. Client A send a request for the public key of client B
2. Client A send client B a request for a symmetric key (** if client A doesn't send this request, client B CAN'T send client A a symmetric key).
3. Client B receives the request
4. Client B sends a request for the public key of client A
5. Client B Creates a symmetric key, encrypts it using client A's public key, and requests to send it to client A
6. Client A receives the symmetric key, decrypts it using his private key
7. Client A and Client B can communicate freely, with encrypted texts and files using their shared symmetric key

The client can send the following requests to the server (number in parantheses is the input code the client needs to enter):
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
*/

#ifndef CLIENT_H
#define CLIENT_H

#include <cstdint>
#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include <fstream>
#include <filesystem>
#include <vector>
#include <optional>
#include <unordered_map>
#include <math.h>
#include <random>

#include "cryptlib.h"
#include <osrng.h>
#include <rsa.h>
#include <base64.h>
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <stdexcept>
#include <immintrin.h>	// _rdrand32_step
#include <iomanip>

using boost::asio::ip::tcp;

namespace ProtocolConstants {

    // General Protocol Details
    constexpr uint8_t CLIENT_VERSION = 2;      // Current protocol version, version 2 because there's file sending implementation

    // Client Request codes (for the user input in the console)
    enum Input_Codes : uint8_t {
        REGISTER = 110,
        CLIENTS_LIST = 120,
        FETCH_OTHER_CLIENT_PUBLIC_KEY = 130,
        FETCH_WAITING_MESSAGES = 140,
        SEND_TEXT_MESSAGE_CODE = 150,
        REQUEST_SYMMETRIC_KEY = 151,
        SEND_SYMMETRIC_KEY = 152,
        SEND_FILE = 153,
        EXIT_CLIENT = 0
    };


    // Request Codes (for the protocol)
    enum Request : uint16_t {
        REGISTER_REQUEST = 600,
        CLIENTS_LIST_REQUEST = 601,
        FETCH_OTHER_CLIENT_PUBLIC_KEY_REQUEST = 602,
        SEND_MESSAGE = 603,
        FETCH_WAITING_MESSAGES_REQUEST = 604
    };

    // Message Codes (for both sending and receiving)
    enum Message : uint8_t {
        REQUEST_SYMMETRICAL_KEY = 1,
        SEND_SYMMETRICAL_KEY = 2,
        SEND_TEXT_MESSAGE = 3,
        SEND_FILE_MESSAGE = 4
    };

    // Server Response Codes
    enum Response : uint16_t {
        REGISTRATION_SUCCESS = 2100,
        CLIENT_LIST_FETCH_SUCCESS = 2101,
        PUBLIC_KEY_FETCH_SUCCESS = 2102,
        MESSAGE_SENT_SUCCESS = 2103,
        FETCHING_INCOMING_MESSAGES_SUCCESS = 2104,
        GENERAL_ERROR = 9000
    };


    // Encryption Keys Sizes:
    constexpr size_t PUBLIC_KEY_SIZE = 160;
    constexpr size_t PRIVATE_KEY_SIZE = 128;
    constexpr size_t SYMMETRIC_KEY_SIZE = 16;

    // General Field Sizes
    constexpr size_t CLIENT_ID_SIZE = 16;           // Size of user ID field (16 bytes)
    constexpr size_t VERSION_SIZE = 1;           // Size of version field (1 byte)
    constexpr size_t REQUEST_CODE_SIZE = 2;                // Size of operation code field (2 byte)
    constexpr size_t RESPONSE_CODE_SIZE = 2;      // Size of Response code size
    constexpr size_t PAYLOAD_FIELD_SIZE = 4;     // Size of payload field size (4 bytes) - containing the size of the following payload
    constexpr size_t CLIENT_NAME_SIZE = 255;    // Size of client name field (255 ASCII string with \n)

    // Message Field Sizes
    constexpr size_t MESSAGE_TYPE_SIZE = 1;    // Size of Message type field size
    constexpr size_t MESSAGE_CONTENT_FIELD_SIZE = 4;    // Size of message content field (describing the size of the following message content)
    constexpr size_t MESSAGE_ID_SIZE = 4;           // Size of Response message ID field size
    constexpr size_t MESSAGE_REQUEST_SYMMETRICAL_KEY_SIZE = 0;  // Size of message request for symmetrical key content field size
    constexpr size_t MESSAGE_REQUEST_HEADER_SIZE = CLIENT_ID_SIZE + MESSAGE_TYPE_SIZE + MESSAGE_CONTENT_FIELD_SIZE; // This is the BASIC message header payload size, not including content.
    constexpr size_t MAXIMUM_TEXT_AND_FILE_SIZE = UINT32_MAX - MESSAGE_REQUEST_HEADER_SIZE; // Max size of the message content size (either text or file).

    // Request Payload Sizes
    constexpr size_t REGISTER_PAYLOAD_SIZE = CLIENT_NAME_SIZE + PUBLIC_KEY_SIZE; // Size of payload for register request operation
    constexpr size_t CLIENT_LIST_AND_FETCH_MESSAGES_PAYLOAD_SIZE = 0; // Size of payload for client list request operation
    constexpr size_t PUBLIC_KEY_FETCH_PAYLOAD_SIZE = CLIENT_ID_SIZE; // Size of payload for public key request operation
    constexpr size_t MAXIMUM_PAYLOAD_SIZE = UINT32_MAX; // Max size of request payload

    // Response Sizes
    constexpr size_t RESPONSE_HEADER_SIZE = VERSION_SIZE + RESPONSE_CODE_SIZE + PAYLOAD_FIELD_SIZE; // Size of general response header size
    constexpr size_t MESSAGE_RESPONSE_HEADER_SIZE = CLIENT_ID_SIZE + MESSAGE_ID_SIZE + MESSAGE_TYPE_SIZE + MESSAGE_CONTENT_FIELD_SIZE; // Size of message response header size

    // Other Constants
    constexpr size_t MAX_PORT_LENGTH = 5;
    constexpr size_t MIN_PORT_VALUE = 0;
    constexpr size_t MAX_PORT_VALUE = 65535;
    const std::string SERVER_FILENAME = "server.info";
    const std::string CLIENT_FILENAME = "me.info";
    constexpr size_t MIN_RANDOM_FILENAME_LENGTH = 16;
    constexpr size_t MAX_RANDOM_FILENAME_LENGTH = 32;

}; // namespace ProtocolConstants

//************************************************
/* Classes declarations and functions*/
//************************************************

/* Class declarations for the Request & Message classes
* All classes inherit from, and are based on the BaseRequest class.
* Each class contains a constructor and a SendRequest function (which uses virtual function and class logic to send a request over Boost socket to the server,
* and chooses the correct request function with the correct details - according to the protocol).
*/
class BaseRequest {
protected:
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
    uint8_t version;
    uint16_t request_code;
    uint32_t payload_size;
public:
    BaseRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size);
    virtual ~BaseRequest() = default;
    virtual void sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const;
};

// Extra client name and public key attributes
class RegisterRequest : public BaseRequest {
protected:
    std::string client_name;
    std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pub_key;
public:
    RegisterRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string client_name, std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE>& pub_key);
    void sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const override;
};

// No extra attributes, and payload size = 0. Relevant to 601 (clients list) & 604 (fetch waiting messages) request codes
class basicRequest : public BaseRequest {
public:
    basicRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size);
    void sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const override;
};

// Extra client id attribute
class PublicKeyRequest : public BaseRequest {
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id;
public:
    PublicKeyRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id);
    void sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const override;
};

// Message inheriting class - Extra client id, message type and message content size attributes.
class Message : public BaseRequest{
protected:
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id;
    uint8_t message_type;
    uint32_t message_content_size;
public:
    Message(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size);
    void sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const override;
};

// No extra attribute
class symmetricKeyRequestMessage : public Message {
public:
    symmetricKeyRequestMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size);
    void sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const override;
};

// Extra symmetric key attribute (encrypted using RSA public key of target client)
class symmetricKeySendMessage : public Message {
protected:
    std::string encrypted_symmetric_key;
public:
    symmetricKeySendMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::string encrypted_symmetric_key);
    void sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const override;
};

// Extra message content attribute (encrypted using AES symmetric key with target client)
class textMessage : public Message {
    std::vector<uint8_t> message_content;
public:
    textMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::vector<uint8_t> message_content);
    void sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const override;
};

// Extra file content attribute (encrypted using AES symmetric key with target client)
class FileSendMessage : public Message {
    std::vector<uint8_t> file_content;
public:
    FileSendMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::vector<uint8_t> file_content);
    void sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const override;
};


/* Class declarations for the Response classes
* All classes inherit from, and are based on the BaseResponse class.
* Each class contains a constructor and a SendRequest function (which uses virtual function and class logic to send a request over Boost socket to the server,
* and chooses the correct request function with the correct details - according to the protocol).
*/
class BaseResponse {
protected:
    uint8_t version;
    uint16_t response_code;
    uint32_t payload_size;
public:
    BaseResponse(uint8_t version, uint16_t response_code, uint32_t payload_size);
    virtual ~BaseResponse() = default;
};

// Extra client id attribute.
class RegisterResponse : public BaseResponse {
protected:
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
public:
    RegisterResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id);
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> getClientID();
};

// No extra attributes.
class ClientsListResponse : public BaseResponse {
public:
    ClientsListResponse(uint8_t version, uint16_t response_code, uint32_t payload_size);
};

// Extra client id and public key attributes.
class PublicKeyResponse : public BaseResponse {
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
    std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pubkey;
public:
    PublicKeyResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pubkey);

};

// Extra client id attribute
class MessageSentResponse : public BaseResponse {
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
    uint32_t message_id;
public:
    MessageSentResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint32_t message_id);
};

// No extra attributes.
class WaitingMessagesFetchResponse : public BaseResponse {
public:
    WaitingMessagesFetchResponse(uint8_t version, uint16_t response_code, uint32_t payload_size);
};

// No extra attributes.
class ErrorResponse : public BaseResponse {
public:
    ErrorResponse(uint8_t version, uint16_t response_code, uint32_t payload_size);
};

/* ClientInfo struct-
* Used as a "recipe" contain the other relevant fields on another client. His username, public key, and shared symmetric key.
*/
struct ClientInfo {
    std::string client_name;
    std::optional<std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE>> public_key;  // Optional field
    std::optional<std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE>> symmetric_key;  // Optional field
    bool symmetric_key_requested; // True if the other client requested a symmetric key

    ClientInfo() = default;

    ClientInfo(const std::string& name) : client_name(name) {}
};

/* ClientHandler class-
* Used as a Singleton class (meaning one instance that is initiated in runtime and used throughout the code, and accessed from anywhere.
* Contains a map of (client id : ClientInfo struct), to change/access other clients info throughout runtime. Saved on memory only.
*/
class ClientHandler {
    std::unordered_map<std::string, ClientInfo> clients;
    // Private constructor for single instance
    ClientHandler() = default;
public:
    // Prevent copying
    ClientHandler(const ClientHandler&) = delete;
    ClientHandler& operator=(const ClientHandler&) = delete;

    // Get Single Instance
    static ClientHandler& getInstance() {
        static ClientHandler instance;
        return instance;
    }

    // Add Client (Only ID + Name Initially)
    void addClient(const std::string& client_id,
        const std::string& client_name);

    // Sets the Public Key of a specific client.
    bool setPublicKey(const std::string& client_id,
        const std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE>& public_key);

    // Sets the Symmetric Key of a specific client.
    bool setSymmetricKey(const std::string& client_id,
        const std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE>& symmetric_key);

    // Sets the SymmetricKeyRequested field of a specific client (which asked for a symmetric key from you) to true.
    bool setSymmetricKeyRequestedToTrue(const std::string& client_id);

    // Get Client id by the client name
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> getClientIDByName(const std::string& name);

    // Get number of clients that are saved right now on memory.
    int numOfClients() const;

    // Get Client (Returns std::optional of ClientInfo struct)
    std::optional<ClientInfo> getClient(const std::string& client_id) const;

    // Helper functions to convert the client id array to string and vice versa
    std::string arrayToStringID(const std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& arr);
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> stringToArrayID(const std::string& str);

    // Print All Clients (Debugging) TODO delete it!!!!!!!!!!!!!!!!!!!!!!
    void printClients() const;
};

/* ServerConnectionManager class- 
* Used to gather the required information, validate it, and access it in order to initiate a connection to the server.
*/
class ServerConnectionManager {
    std::string ip;
    std::string port;
    boost::asio::io_context io_context;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;
public:
    ServerConnectionManager(); // Constructor, which validates and then reads IP & Port from "server.info" file

    // Checks if the port and ip gathered from the file are valid
    bool isPortValid(const std::string& tmp_port);
    bool isIPvalid(const std::string& tmp_ip);
    
    // Validate the server.info file
    std::string validate_server_file(std::ifstream& file);

    // Reads the IP and Port from the file AFTER validaing it.
    std::string readIPfromFile(const std::string& line);
    std::string readPortfromFile(const std::string& line);
    
    // Connects to the server and returns a smart pointer to the socket.
    std::shared_ptr<boost::asio::ip::tcp::socket> connectToServer(); // Connect on demand

    std::string getIP() const { return ip; }
    std::string getPort() const { return port; }
};

//************************************************
/* Text Validation and Manipulation Functions*/
//************************************************

// Converts public key string to array.
std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> stringToArrayPubKey(const std::string& str);

// Creates a random file name, between 8 and 32 characters long, with only ASCII characters
std::string createRandomFileName();

// Validates that a string contains ONLY ascii characters.
bool containsOnlyASCII(const std::string& name);

// Validates a client name.
bool isValidClientName(const std::string& client_name);

// Converts a 16 byte client id to ASCII representation, where every 2 characters represent an hex value with 8 bits.
std::string uuidToString_file(const std::array < uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& client_id);

// Converts a size 32 characters client id string, where each 2 characters are a 8-bit hex value to a 16 byte client id array of uint8_t
std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> stringToUUID_file(const std::string& client_id_string);

//************************************************
/* File Utility Functions for "me.info" file*/
//************************************************

// Creates a client.info file, and inserts the correct information according to the protocol standards.
bool CreateClientInfoFile(std::string filename, std::string username, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, std::string private_key_base64);

// Reads the me.info file and returns the client id from the file.
std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> fetchClientIdFromFile();

// Reads the me.info file and returns the private key from the file (still in base 64)
std::string fetchPrivateKeyFromFile();

//********************************************
/* Utility Functions*/
//********************************************

// Asks the user for a client username, and return the client's ID.
std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> inputUsernameAndGetClientID();

// Utility function that reads a fixed amount of bytes from the socket, validates that it read the correct amount of bytes, and then returns it as a vector.
std::vector<uint8_t> readFixedSize(boost::asio::ip::tcp::socket& socket, size_t size);

// "Flushes" the buffer given to it as a parameter (consumes and clears it basically)
void flushBuffer(boost::asio::streambuf& buffer, std::istream& stream);

// Checks if a file exists using the filename
bool doesFileExist(const std::string& filename);

//********************************************
/* Main Client Logic Functions*/
//********************************************

// Parses the response coming back from the server according to the protocol, using the readFixedSize function.
std::unique_ptr<BaseResponse> parseResponse(std::shared_ptr<tcp::socket>& socket);

// Handles the logic to register a client to the server
void handleClientRegister(std::unique_ptr<BaseRequest>& request, std::unique_ptr<BaseResponse>& response, ServerConnectionManager& serverConnection);

// Handles the logic to make a clients list request
void handleClientsListAndFetchMessagesRequest(int operation_code, std::unique_ptr<BaseRequest>& request, std::unique_ptr<BaseResponse>& response, ServerConnectionManager& serverConnection);

// Handles the public key request
void handlePublicKeyRequest(std::unique_ptr<BaseRequest>& request, std::unique_ptr<BaseResponse>& response, ServerConnectionManager& serverConnection);

// Handles the 4 types of message types sending and response.
void handleMessageSend(int operation_code, std::unique_ptr<BaseRequest>& request, std::unique_ptr<BaseResponse>& response, ServerConnectionManager& serverConnection);

// Handles the user input, by calling the handle request function (respective to the relevant request)
void handleUserInput(int operation_code, ServerConnectionManager& serverConnection);

/* Main Function - main loop*/
int main();


//******************************************************************************************
//*	Wrapper Function and Classes Provided externally, for use with the project's demands.
//******************************************************************************************

// RSA Wrappers
class RSAPublicWrapper
{
public:
    static const unsigned int KEYSIZE = 160;
    static const unsigned int BITS = 1024;

private:
    CryptoPP::AutoSeededRandomPool _rng;
    CryptoPP::RSA::PublicKey _publicKey;

    RSAPublicWrapper(const RSAPublicWrapper& rsapublic);
    RSAPublicWrapper& operator=(const RSAPublicWrapper& rsapublic);
public:

    RSAPublicWrapper(const char* key, unsigned int length);
    RSAPublicWrapper(const std::string& key);
    ~RSAPublicWrapper();

    std::string getPublicKey() const;
    char* getPublicKey(char* keyout, unsigned int length) const;

    std::string encrypt(const std::string& plain);
    std::string encrypt(const char* plain, unsigned int length);
};


class RSAPrivateWrapper
{
public:
    static const unsigned int BITS = 1024;

private:
    CryptoPP::AutoSeededRandomPool _rng;
    CryptoPP::RSA::PrivateKey _privateKey;

    RSAPrivateWrapper(const RSAPrivateWrapper& rsaprivate);
    RSAPrivateWrapper& operator=(const RSAPrivateWrapper& rsaprivate);
public:
    RSAPrivateWrapper();
    RSAPrivateWrapper(const char* key, unsigned int length);
    RSAPrivateWrapper(const std::string& key);
    ~RSAPrivateWrapper();

    std::string getPrivateKey() const;
    char* getPrivateKey(char* keyout, unsigned int length) const;

    std::string getPublicKey() const;
    char* getPublicKey(char* keyout, unsigned int length) const;

    std::string decrypt(const std::string& cipher);
    std::string decrypt(const char* cipher, unsigned int length);
};


// Base64 Wrapper
class Base64Wrapper
{
public:
    static std::string encode(const std::string& str);
    static std::string decode(const std::string& str);
};

// AES Wrapper
class AESWrapper
{
public:
    static const unsigned int DEFAULT_KEYLENGTH = 16;
private:
    unsigned char _key[DEFAULT_KEYLENGTH];
    AESWrapper(const AESWrapper& aes);
public:
    static unsigned char* GenerateKey(unsigned char* buffer, unsigned int length);

    AESWrapper();
    AESWrapper(const unsigned char* key, unsigned int size);
    ~AESWrapper();

    const unsigned char* getKey() const;

    std::string encrypt(const char* plain, unsigned int length);
    std::string decrypt(const char* cipher, unsigned int length);
};

 
void hexify(const unsigned char* buffer, unsigned int length);


#endif // CLIENT.H