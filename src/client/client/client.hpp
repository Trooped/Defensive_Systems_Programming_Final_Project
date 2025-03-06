/**
@File: client.h
@Author: Omri Peretz
@Date: March 2025
@Assignment: Maman 15
@Course: Defensive Systems Programming

@Description:
This file is a client program (.h file) written in C++, that communicates with a server program. Used for a message transfer protocol between different clients.
The client and server communicate over TCP, with a compatible, agreed upon protocol. The data is being sent in little endian format.

The client can send the following requests to the server:
- 600: Registration request
- 601: Client list request
- 602: Public key of other client request
- 603: Send message request
- 603 - 1: Symmetrical key from other client request
- 603 - 2: Symmetrical key to other client request
- 603 - 3: Text message send request 
- 603 - 4: File send request
- 604: Incoming messages addressed to the client request

The server will do the operation and respond with the following statuses:
- 2100: Success: Registration suceeded
- 2101: Success: List of clients sent
- 2102: Success: Public key sent
- 2103: Success: Message sent to client (held at server database until client requests to read it)
- 2104: Success: List of incoming messages sent
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
    constexpr uint8_t CLIENT_VERSION = 2;      // Current protocol version
    //constexpr uint16_t MAX_FILENAME_LENGTH = 255; // Maximum allowed filename length


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

    // Message Codes
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
    //ADDDDDDDDDDDDDDDDDDDDDDDDD THE KEYS SIZES!!!!!!!!!!!!
    constexpr size_t PUBLIC_KEY_SIZE = 160;
    constexpr size_t PRIVATE_KEY_SIZE = 128;
    constexpr size_t SYMMETRIC_KEY_SIZE = 16;

    // General Request Sizes
    constexpr size_t CLIENT_ID_SIZE = 16;           // Size of user ID field (16 bytes)
    constexpr size_t VERSION_SIZE = 1;           // Size of version field (1 byte)
    constexpr size_t REQUEST_CODE_SIZE = 1;                // Size of operation code field (2 byte)
    constexpr size_t PAYLOAD_FIELD_SIZE = 4;     // Size of payload field size (4 bytes) - containing the size of the following payload
    constexpr size_t CLIENT_NAME_SIZE = 255;    // Size of client name field (255 ASCII string with \n)

    // Message Send Request Sizes
    constexpr size_t MESSAGE_TYPE_SIZE = 1;    // Size of Message type field size
    constexpr size_t MESSAGE_CONTENT_FIELD_SIZE = 4;    // Size of message content field (describing the size of the following message content)
    constexpr size_t MESSAGE_ID_SIZE = 4;
    constexpr size_t MESSAGE_REQUEST_SYMMETRICAL_KEY_SIZE = 0;
    constexpr size_t MAXIMUM_TEXT_AND_FILE_SIZE = UINT32_MAX;

    // Request Payload Sizes
    constexpr size_t REGISTER_PAYLOAD_SIZE = CLIENT_NAME_SIZE + PUBLIC_KEY_SIZE;
    constexpr size_t CLIENT_LIST_AND_FETCH_MESSAGES_PAYLOAD_SIZE = 0; 
    constexpr size_t PUBLIC_KEY_FETCH_PAYLOAD_SIZE = CLIENT_ID_SIZE;
    constexpr size_t MESSAGE_REQUEST_BASIC_PAYLOAD_SIZE = CLIENT_ID_SIZE + MESSAGE_TYPE_SIZE + MESSAGE_CONTENT_FIELD_SIZE; // This is the BASIC message payload size, the content will increase it 

    // Response Sizes
    constexpr size_t RESPONSE_CODE_SIZE = 2;
    constexpr size_t BASIC_RESPONSE_SIZE = VERSION_SIZE + RESPONSE_CODE_SIZE + PAYLOAD_FIELD_SIZE;
    constexpr size_t MESSAGE_HEADER_SIZE = CLIENT_ID_SIZE + MESSAGE_ID_SIZE + MESSAGE_TYPE_SIZE + MESSAGE_CONTENT_FIELD_SIZE;


}; // namespace Protocol

// Class declarations for the Request & Message classes
class BaseRequest {
protected:
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
    uint8_t version;
    uint16_t request_code;
    uint32_t payload_size;
public:
    BaseRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size);
    virtual ~BaseRequest() = default;
    virtual void sendRequest(tcp::socket& socket) const;
};

class RegisterRequest : public BaseRequest {
protected:
    std::string client_name;
    std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> public_key;
public:
    RegisterRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string client_name, std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> public_key);
    void sendRequest(tcp::socket& socket);
};

// No extra attributes, and payload size = 0. Relevant to 601 (clients list) & 604 (fetch waiting messages) request codes
class basicRequest : public BaseRequest {
public:
    basicRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size);
    void sendRequest(tcp::socket& socket);
};

class PublicKeyRequest : public BaseRequest {
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id;
public:
    PublicKeyRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id);
    void sendRequest(tcp::socket& socket);
};


class Message : public BaseRequest{
protected:
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id;
    uint8_t message_type;
    uint32_t message_content_size;
public:
    Message(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size);
    void sendRequest(tcp::socket& socket);
};


class symmetricKeyRequestMessage : public Message {

public:
    symmetricKeyRequestMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size);
    void sendRequest(tcp::socket& socket);

};

class symmetricKeySendMessage : public Message {
protected:
    std::string encrypted_symmetric_key;
public:
    symmetricKeySendMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::string encrypted_symmetric_key);
    void sendRequest(tcp::socket& socket);
};

class textMessage : public Message {
    std::vector<uint8_t> message_content;
public:
    textMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::vector<uint8_t> message_content);
    void sendRequest(tcp::socket& socket);
};

class FileSendMessage : public Message {
    std::vector<uint8_t> file_content;
public:
    FileSendMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::vector<uint8_t> file_content);
    void sendRequest(tcp::socket& socket);
};


// Class declarations for the Response classes - coming from the server

class BaseResponse {
protected:
    uint8_t version;
    uint16_t response_code;
    uint32_t payload_size;
public:
    BaseResponse(uint8_t version, uint16_t response_code, uint32_t payload_size);
    virtual ~BaseResponse() = default;
};

class RegisterResponse : public BaseResponse {
protected:
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
public:
    RegisterResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id);
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> getClientID();
};

class ClientsListResponse : public BaseResponse {
public:
    ClientsListResponse(uint8_t version, uint16_t response_code, uint32_t payload_size);
};

class PublicKeyResponse : public BaseResponse {
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
    std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pubkey;
public:
    PublicKeyResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pubkey);

};

class MessageSentResponse : public BaseResponse {
    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
    uint32_t message_id;
public:
    MessageSentResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint32_t message_id);
};


class WaitingMessagesFetchResponse : public BaseResponse {
public:
    WaitingMessagesFetchResponse(uint8_t version, uint16_t response_code, uint32_t payload_size);
};

class ErrorResponse : public BaseResponse {
public:
    ErrorResponse(uint8_t version, uint16_t response_code, uint32_t payload_size);
};

struct ClientInfo {
    std::string client_name;
    std::optional<std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE>> public_key;  // Optional field
    std::optional<std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE>> symmetric_key;  // Optional field

    ClientInfo() = default;

    ClientInfo(const std::string& name) : client_name(name) {}
};

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
    void addClient(const std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& client_id,
        const std::string& client_name);

    // Set Public Key
    bool setPublicKey(const std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& client_id,
        const std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE>& public_key);

    // Set Symmetric Key
    bool setSymmetricKey(const std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& client_id,
        const std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE>& symmetric_key);

    std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> getClientIDByName(const std::string& name);

    // Get Client (Returns std::optional)
    std::optional<ClientInfo> getClient(const std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& client_id) const;

    // Print All Clients (Debugging)
    void printClients() const;
};

class ServerConnectionManager {
    std::string ip;
    std::string port;
    boost::asio::io_context io_context;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;

public:
    ServerConnectionManager(); // Constructor reads IP & Port

    bool isPortValid(const string& port);
    bool isIPvalid(const string& ip);
    void clearFileAndResetPointer(std::ifstream& file);
    std::string readIPfromFile(const std::string& line);
    std::string readPortfromFile(const std::string& line);
    std::string validate_server_file(std::ifstream& file);

    std::shared_ptr<boost::asio::ip::tcp::socket> connectToServer(); // Connect on demand
    std::string getIP() const { return ip; }
    std::string getPort() const { return port; }
};



/*
*	Wrapper Function and Classes Provided externally, for use with the project's demands.
*/

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

 



#endif // CLIENT.H