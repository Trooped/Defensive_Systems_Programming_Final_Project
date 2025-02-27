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
#include <fstream>
#include <filesystem>
#include <vector>

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



namespace ProtocolConstants {

    // General Protocol Details
    constexpr uint8_t CLIENT_VERSION = 1;      // Current protocol version
    //constexpr uint16_t MAX_FILENAME_LENGTH = 255; // Maximum allowed filename length


    // Client Request codes (for the user input in the console)
    enum Input_Codes : uint8_t {
        REGISTER = 110,
        CLIENTS_LIST = 120,
        FETCH_OTHER_CLIENT_PUBLIC_KEY = 130,
        FETCH_WAITING_MESSAGES = 140,
        SEND_TEXT_MESSAGE_CODE = 150,
        SEND_REQUEST_SYMMETRIC_KEY = 151,
        SEND_SYMMETRIC_KEY = 152,
        EXIT_CLIENT = 0
    };


    // Request Codes (for the protocol)
    enum Request : uint8_t {
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
        //SEND_FILE = 4
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

    // General Request Sizes
    constexpr size_t CLIENT_ID_SIZE = 16;           // Size of user ID field (16 bytes)
    constexpr size_t VERSION_SIZE = 1;           // Size of version field (1 byte)
    constexpr size_t CODE_SIZE = 1;                // Size of operation code field (2 byte)
    constexpr size_t PAYLOAD_FIELD_SIZE = 4;     // Size of payload field size (4 bytes) - containing the size of the following payload
    constexpr size_t CLIENT_NAME_SIZE = 255;    // Size of client name field (255 ASCII string with \n)

    // Message Send Request Sizes
    constexpr size_t MESSAGE_TYPE_SIZE = 1;    // Size of Message type field size
    constexpr size_t MESSAGE_CONTENT_FIELD_SIZE = 4;    // Size of message content field (describing the size of the following message content)

    // Request Payload Sizes
    constexpr size_t REGISTER_PAYLOAD_SIZE = CLIENT_NAME_SIZE + PUBLIC_KEY_SIZE;
    constexpr size_t CLIENT_LIST_AND_FETCH_MESSAGES_PAYLOAD_SIZE = 0; 
    constexpr size_t PUBLIC_KEY_FETCH_PAYLOAD_SIZE = CLIENT_ID_SIZE;
    constexpr size_t MESSAGE_REQUEST_BASIC_PAYLOAD_SIZE = CLIENT_ID_SIZE + MESSAGE_TYPE_SIZE + MESSAGE_CONTENT_FIELD_SIZE; // This is the BASIC message payload size, the content will increase it 


    // More constants
    constexpr std::array<uint8_t, 16> DEFAULT_CLIENT_ID = AAAAAAAAAAAAAAAA; // Default client ID, to use when registering

    // Encryption Keys Sizes:
    //ADDDDDDDDDDDDDDDDDDDDDDDDD THE KEYS SIZES!!!!!!!!!!!!
    constexpr size_t PUBLIC_KEY_SIZE = 160;

    /*
    constexpr size_t BASIC_REQUEST_SIZE = USER_ID_SIZE + VERSION_SIZE + OP_SIZE;  // Fixed header size in bytes, consiting of only
    constexpr size_t NAME_LEN_SIZE = 2;          // Size of name_len field (2 bytes)
    constexpr size_t METADATA_REQUEST_SIZE = BASIC_REQUEST_SIZE + NAME_LEN_SIZE;
    */

}; // namespace Protocol

class BaseRequest {
protected:
    std::array<uint8_t, 16> client_id;
    uint8_t version;
    uint16_t request_code;
    uint32_t payload_size;
public:
    BaseRequest(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size);
    /* MAYBE ADD THIS LATER? IS IT NECESSARY?
    const std::array<uint8_t, 16>& getClientIdBytes() const {
        return client_id;
    }
    */
    virtual ~BaseRequest() = default;
};

class registerRequest : public BaseRequest {
protected:
    std::string client_name;
    std::string public_key;
public:
    registerRequest(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string client_name, std::string public_key);
};

// No extra attributes, and payload size = 0. Relevant to 601 & 604 request codes
class basicRequest : public BaseRequest {
public:
    basicRequest(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size);
};

class publicKeyRequest : public BaseRequest {
    std::string target_client_id;
public:
    publicKeyRequest(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id);
};


class Message : public BaseRequest{
protected:
    std::string target_client_id;
    uint8_t message_type;
    uint32_t message_content_size;
public:
    Message(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size);
};


class symmetricKeyRequestMessage : public Message {

public:
    symmetricKeyRequestMessage(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size);

};

class symmetricKeySendMessage : public Message {
protected:
    // ADD THE SYMMETRICAL KEY SIZE AND ATTRIBUTE, for right now let's say it's 160 bytes string
    std::string encrypted_symmetric_key;
public:
    symmetricKeySendMessage(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size, std::string encrypted_symmetric_key);
};

class textMessage : public Message {
    std::vector<uint8_t> message_content;
public:
    textMessage(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size, std::vector<uint8_t> message_content);
};














// Cryptopp Wrapper classes & functions declarations

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