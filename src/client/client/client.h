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

namespace ProtocolConstants {

    // General Protocol Details
    constexpr uint8_t CLIENT_VERSION = 1;      // Current protocol version
    //constexpr uint16_t MAX_FILENAME_LENGTH = 255; // Maximum allowed filename length

    //constexpr char BASE_DIRECTORY[] = "C:\\backupsvr";
    constexpr int PORT = 1234;

    // Client Request codes (for the user input in the console)
    enum Input_Codes : uint8_t {
        REGISTER = 110,
        CLIENTS_LIST = 120,
        FETCH_OTHER_CLIENT_PUBLIC_KEY = 130,
        FETCH_WAITING_MESSAGES = 140,
        SEND_TEXT_MESSAGE = 150,
        SEND_REQUEST_SYMMETRIC_KEY = 151,
        SEND_SYMMETRIC_KEY = 152,
        EXIT_CLIENT = 0
    };


    // Request Codes (for the protocol)
    enum Request : uint8_t {
        REGISTER = 600,
        CLIENTS_LIST = 601,
        FETCH_OTHER_CLIENT_PUBLIC_KEY = 602,
        SEND_MESSAGE = 603,
        FETCH_WAITING_MESSAGES = 604
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
    constexpr size_t CLIENT_NAME_SIZE = 255;    // Size of client name fiedl (255 ASCII string with \n)

    // Encryption Keys Sizes:
    //ADDDDDDDDDDDDDDDDDDDDDDDDD THE KEYS SIZES!!!!!!!!!!!!

    /*
    constexpr size_t BASIC_REQUEST_SIZE = USER_ID_SIZE + VERSION_SIZE + OP_SIZE;  // Fixed header size in bytes, consiting of only
    constexpr size_t NAME_LEN_SIZE = 2;          // Size of name_len field (2 bytes)
    constexpr size_t METADATA_REQUEST_SIZE = BASIC_REQUEST_SIZE + NAME_LEN_SIZE;
    */

}; // namespace Protocol

class Request {
protected:
    std::string client_id;
    uint8_t version;
    uint16_t request_code;
    uint32_t payload_size;
public:
    Request(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size);
};

class registerRequest : public Request {
protected:
    std::string client_name;
    std::string public_key;
public:
    registerRequest(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string client_name, std::string public_key);
};

// No extra attributes, and payload size = 0. Relevant to 601 & 604 request codes
class basicRequest : public Request {    
public:
    basicRequest(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size);
};

class publicKeyRequest : public Request {
    std::string target_client_id;
public:
    publicKeyRequest(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id);
};


class Message : public Request{
protected:
    std::string target_client_id;
    uint8_t message_type;
    uint32_t message_content_size;
public:
    Message(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size);
};


class symmetricKeyRequestMessage : public Message {

public:
    symmetricKeyRequestMessage(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size);

};

class symmetricKeySendMessage : public Message {
protected:
    // ADD THE SYMMETRICAL KEY SIZE AND ATTRIBUTE, for right now let's say it's 160 bytes string
    std::string encrypted_symmetric_key;
public:
    symmetricKeySendMessage(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size, std::string encrypted_symmetric_key);
};

class textMessage : public Message {
    std::vector<uint8_t> message_content;
public:
    textMessage(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size, std::vector<uint8_t> message_content);
};



 



#endif // CLIENT.H