/**
@File: client.cpp
@Author: Omri Peretz
@Date: March 2025
@Assignment: Maman 15
@Course: Defensive Systems Programming

@Description:
This file is a client program written in C++, that communicates with a server program. Used for a message transfer protocol between different clients.
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

The client can send the following requests to the server (number in parentheses is the input code the client needs to enter):
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

#include "client.hpp"

using boost::asio::ip::tcp;
using namespace std;

#include <regex> //TODO delete this.


//*******************************************************************
/* Classes declarations and functions*/
//*******************************************************************

/* Class declarations for the Request & Message classes
* All classes inherit from, and are based on the BaseRequest class.
* Each class contains a constructor and a SendRequest function (which uses virtual function and class logic to send a request over Boost socket to the server,
* and chooses the correct request function with the correct details - according to the protocol).
*/
BaseRequest::BaseRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size)
	: client_id{ client_id }, version{ version }, request_code{ request_code }, payload_size{ payload_size } { }
void BaseRequest::sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);

	uint16_t request_code_con = boost::endian::native_to_little(request_code);
	request_stream.write(reinterpret_cast<const char*>(&request_code_con), sizeof(request_code));

	uint32_t payload_size_con = boost::endian::native_to_little(payload_size);
	request_stream.write(reinterpret_cast<const char*>(&payload_size_con), sizeof(payload_size));
	
	boost::asio::write(*socket, buffer);
}

// Extra client name and public key attributes
RegisterRequest::RegisterRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string client_name, std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE>& pub_key)
	: BaseRequest(client_id, version, request_code, payload_size), client_name(client_name), pub_key(pub_key) { }
void RegisterRequest::sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const {


	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);

	uint16_t request_code_con = boost::endian::native_to_little(request_code);
	request_stream.write(reinterpret_cast<const char*>(&request_code_con), sizeof(request_code));

	uint32_t payload_size_con = boost::endian::native_to_little(payload_size);
	request_stream.write(reinterpret_cast<const char*>(&payload_size_con), sizeof(payload_size));


	std::string temp_name = client_name;
	// Pad the temp name with '\0' to send a fixed 255 bytes name.
	while (temp_name.length() < ProtocolConstants::CLIENT_NAME_SIZE) {
		temp_name += '\0';
	}
	const char* char_name = temp_name.c_str();
	request_stream.write(char_name, ProtocolConstants::CLIENT_NAME_SIZE);

	request_stream.write(reinterpret_cast<const char*>(pub_key.data()), pub_key.size());

	try {
		boost::asio::write(*socket, buffer);
	}
	catch (const std::exception& e) {
		cerr << "Failed to send request: " << e.what() << endl;
	}
}

// No extra attributes, and payload size = 0. Relevant to 601 (clients list) & 604 (fetch waiting messages) request codes
basicRequest::basicRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size)
	: BaseRequest(client_id, version, request_code, payload_size) { }
void basicRequest::sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);

	uint16_t request_code_con = boost::endian::native_to_little(request_code);
	request_stream.write(reinterpret_cast<const char*>(&request_code_con), sizeof(request_code));

	uint32_t payload_size_con = boost::endian::native_to_little(payload_size);
	request_stream.write(reinterpret_cast<const char*>(&payload_size_con), sizeof(payload_size));

	try {
		boost::asio::write(*socket, buffer);
	}
	catch (const std::exception& e) {
		cerr << "Failed to send request: " << e.what() << endl;
	}
}

// Extra client id attribute
PublicKeyRequest::PublicKeyRequest(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id)
	: BaseRequest(client_id, version, request_code, payload_size), target_client_id(target_client_id) { }
void PublicKeyRequest::sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);

	uint16_t request_code_con = boost::endian::native_to_little(request_code);
	request_stream.write(reinterpret_cast<const char*>(&request_code_con), sizeof(request_code));

	uint32_t payload_size_con = boost::endian::native_to_little(payload_size);
	request_stream.write(reinterpret_cast<const char*>(&payload_size_con), sizeof(payload_size));

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), target_client_id.size());

	try {
		boost::asio::write(*socket, buffer);
	}
	catch (const std::exception& e) {
		cerr << "Failed to send request: " << e.what() << endl;
	}
}

// Message inheriting class - Extra client id, message type and message content size attributes.
Message::Message(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size)
	: BaseRequest(client_id, version, request_code, payload_size), target_client_id(target_client_id), message_type(message_type), message_content_size(message_content_size) { }
void Message::sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);

	uint16_t request_code_con = boost::endian::native_to_little(request_code);
	request_stream.write(reinterpret_cast<const char*>(&request_code_con), sizeof(request_code));

	uint32_t payload_size_con = boost::endian::native_to_little(payload_size);
	request_stream.write(reinterpret_cast<const char*>(&payload_size_con), sizeof(payload_size));

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), target_client_id.size());
	request_stream.put(message_type);

	uint32_t content_size_con = boost::endian::native_to_little(message_content_size);
	request_stream.write(reinterpret_cast<const char*>(&content_size_con), sizeof(message_content_size));

	try {
		boost::asio::write(*socket, buffer);
	}
	catch (const std::exception& e) {
		cerr << "Failed to send request: " << e.what() << endl;
	}
}

// No extra attribute for Message
symmetricKeyRequestMessage::symmetricKeyRequestMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size)
	: Message(client_id, version, request_code, payload_size, target_client_id, message_type, message_content_size) { }
void symmetricKeyRequestMessage::sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);

	uint16_t request_code_con = boost::endian::native_to_little(request_code);
	request_stream.write(reinterpret_cast<const char*>(&request_code_con), sizeof(request_code));

	uint32_t payload_size_con = boost::endian::native_to_little(payload_size);
	request_stream.write(reinterpret_cast<const char*>(&payload_size_con), sizeof(payload_size));

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), target_client_id.size());
	request_stream.put(message_type);

	uint32_t content_size_con = boost::endian::native_to_little(message_content_size);
	request_stream.write(reinterpret_cast<const char*>(&content_size_con), sizeof(message_content_size));
	// No content sent
	try {
		boost::asio::write(*socket, buffer);
	}
	catch (const std::exception& e) {
		cerr << "Failed to send request: " << e.what() << endl;
	}
}

// Extra symmetric key attribute (encrypted using RSA public key of target client)
symmetricKeySendMessage::symmetricKeySendMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::string encrypted_symmetric_key)
	: Message(client_id, version, request_code, payload_size, target_client_id, message_type, message_content_size), encrypted_symmetric_key(encrypted_symmetric_key) { }
void symmetricKeySendMessage::sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), ProtocolConstants::CLIENT_ID_SIZE);
	request_stream.put(version);

	uint16_t request_code_con = boost::endian::native_to_little(request_code);
	request_stream.write(reinterpret_cast<const char*>(&request_code_con), ProtocolConstants::REQUEST_CODE_SIZE);

	uint32_t payload_size_con = boost::endian::native_to_little(payload_size);
	request_stream.write(reinterpret_cast<const char*>(&payload_size_con), ProtocolConstants::PAYLOAD_FIELD_SIZE);

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), ProtocolConstants::CLIENT_ID_SIZE);
	request_stream.put(message_type);

	uint32_t content_size_con = boost::endian::native_to_little(message_content_size);
	request_stream.write(reinterpret_cast<const char*>(&content_size_con), ProtocolConstants::MESSAGE_CONTENT_FIELD_SIZE);
	request_stream.write(reinterpret_cast<const char*>(encrypted_symmetric_key.data()), message_content_size);

	try {
		boost::asio::write(*socket, buffer);
	}
	catch (const std::exception& e) {
		cerr << "Failed to send request: " << e.what() << endl;
	}
}

// Extra message content attribute (encrypted using AES symmetric key with target client)
textMessage::textMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::vector<uint8_t> message_content)
	: Message(client_id, version, request_code, payload_size, target_client_id, message_type, message_content_size), message_content(message_content) { }
void textMessage::sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());
	request_stream.put(version);

	uint16_t request_code_con = boost::endian::native_to_little(request_code);
	request_stream.write(reinterpret_cast<const char*>(&request_code_con), sizeof(request_code));

	uint32_t payload_size_con = boost::endian::native_to_little(payload_size);
	request_stream.write(reinterpret_cast<const char*>(&payload_size_con), sizeof(payload_size));

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), target_client_id.size());
	request_stream.put(message_type);

	uint32_t content_size_con = boost::endian::native_to_little(message_content_size);
	request_stream.write(reinterpret_cast<const char*>(&content_size_con), sizeof(message_content_size));
	request_stream.write(reinterpret_cast<const char*>(message_content.data()), message_content_size);
	try {
		boost::asio::write(*socket, buffer);
	}
	catch (const std::exception& e) {
		cerr << "Failed to send request: " << e.what() << endl;
	}
}

// Extra file content attribute (encrypted using AES symmetric key with target client)
FileSendMessage::FileSendMessage(std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::vector<uint8_t> file_content)
	: Message(client_id, version, request_code, payload_size, target_client_id, message_type, message_content_size), file_content(file_content) { }
void FileSendMessage::sendRequest(std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());
	request_stream.put(version);

	uint16_t request_code_con = boost::endian::native_to_little(request_code);
	request_stream.write(reinterpret_cast<const char*>(&request_code_con), sizeof(request_code));

	uint32_t payload_size_con = boost::endian::native_to_little(payload_size);
	request_stream.write(reinterpret_cast<const char*>(&payload_size_con), sizeof(payload_size));

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), target_client_id.size());
	request_stream.put(message_type);

	uint32_t content_size_con = boost::endian::native_to_little(message_content_size);
	request_stream.write(reinterpret_cast<const char*>(&content_size_con), sizeof(message_content_size));
	request_stream.write(reinterpret_cast<const char*>(file_content.data()), message_content_size);
	try {
		boost::asio::write(*socket, buffer);
	}
	catch (const std::exception& e) {
		cerr << "Failed to send request: " << e.what() << endl;
	}
}


/* Class declarations for the Response classes
* All classes inherit from, and are based on the BaseResponse class.
* Each class contains a constructor and a SendRequest function (which uses virtual function and class logic to send a request over Boost socket to the server,
* and chooses the correct request function with the correct details - according to the protocol).
*/
BaseResponse::BaseResponse(uint8_t version, uint16_t response_code, uint32_t payload_size)
	: version{ version }, response_code{ response_code }, payload_size{ payload_size } { }

// Extra client id attribute.
RegisterResponse::RegisterResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id)
	: BaseResponse(version, response_code, payload_size), client_id(client_id) { }
std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> RegisterResponse::getClientID() {
	return client_id;
}

// No extra attributes.
ClientsListResponse::ClientsListResponse(uint8_t version, uint16_t response_code, uint32_t payload_size)
	: BaseResponse(version, response_code, payload_size) { }

// Extra client id and public key attributes.
PublicKeyResponse::PublicKeyResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pubkey)
	: BaseResponse(version, response_code, payload_size), client_id(client_id), pubkey(pubkey) { }

// Extra client id attribute
MessageSentResponse::MessageSentResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint32_t message_id)
	: BaseResponse(version, response_code, payload_size), client_id(client_id), message_id(message_id) { }

// No extra attributes.
WaitingMessagesFetchResponse::WaitingMessagesFetchResponse(uint8_t version, uint16_t response_code, uint32_t payload_size)
	: BaseResponse(version, response_code, payload_size) { }

// No extra attributes. Returns a general Error 9000 from the server.
ErrorResponse::ErrorResponse(uint8_t version, uint16_t response_code, uint32_t payload_size)
	: BaseResponse(version, response_code, payload_size) { }



/* ClientHandler class-
* Used as a Singleton class (meaning one instance that is initiated in runtime and used throughout the code, and accessed from anywhere.
* Contains a map of (client id : ClientInfo struct), to change/access other clients info throughout runtime. Saved on memory only.
*/
// Adds a client to the clients map, if it doesn't exist.
void ClientHandler::addClient(const std::string& client_id, const std::string& client_name) {
	clients.insert({ client_id, ClientInfo(client_name) });
}

// Sets the Public Key of a specific client.
bool ClientHandler::setPublicKey(const std::string& client_id, const std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE>& public_key) {
	auto it = clients.find(client_id);
	if (it != clients.end()) {
		it->second.public_key = std::make_optional(public_key);
		return true;
	}
	return false; // Client not found in list
}

// Sets the Symmetric Key of a specific client.
bool ClientHandler::setSymmetricKey(const std::string& client_id, const std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE>& symmetric_key) {
	auto it = clients.find(client_id);
	if (it != clients.end()) {
		it->second.symmetric_key = symmetric_key;
		return true;
	}
	return false; // Client not found in list
}

// Sets the SymmetricKeyRequested field of a specific client (which asked for a symmetric key from you) to true.
bool ClientHandler::setSymmetricKeyRequestedToTrue(const std::string& client_id) {
	auto it = clients.find(client_id);
	if (it != clients.end()) {
		it->second.symmetric_key_requested = true;
		return true;
	}
	return false; // Client not found in list
}

// Get Client id by the client name
std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> ClientHandler::getClientIDByName(const std::string& name) {
	for (const auto& it : clients) {
		if (it.second.client_name == name) {
			return stringToArrayID(it.first);  // Return client_id as array
		}
	}
	throw std::runtime_error("Can't find " + name + " inside clients list, please check the name again, or ask for clients list again.");
}

// Get number of clients that are saved right now on memory
int ClientHandler::numOfClients() const {
	int ctr = 0;
	for (const auto& it : clients) {
		ctr++;
	}
	return ctr;
}

// Get Client (Returns std::optional of ClientInfo struct)
std::optional<ClientInfo> ClientHandler::getClient(const std::string& client_id) const {
	auto it = clients.find(client_id);
	if (it != clients.end()) {
		return it->second;
	}
	return std::nullopt; // Client not found in list
}

// Helper functions to convert the client id array to string and vice versa
std::string ClientHandler::arrayToStringID(const std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& arr) {
	return std::string(arr.begin(), arr.end());  // Convert directly
}
std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> ClientHandler::stringToArrayID(const std::string& str) {
	std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> arr = {};  // Initialize with zeros
	std::memcpy(arr.data(), str.data(), std::min(str.size(), ProtocolConstants::CLIENT_ID_SIZE));  // Copy data
	return arr;
}


/* ServerConnectionManager class-
* Used to gather the required information, validate it, and access it in order to initiate a connection to the server.
*/

// Constructor, which validates and then reads IP & Port from "server.info" file
ServerConnectionManager::ServerConnectionManager() {
	const std::string filename = ProtocolConstants::SERVER_FILENAME;

	if (!filesystem::exists(filename)) {
		throw std::runtime_error("File " + filename + " doesn't exist.");
	}
	std::ifstream file(filename);
	if (!file.is_open()) {
		throw std::runtime_error("Failed to open file: " + filename);
	}

	std::string info_line = validate_server_file(file);
	this->ip = readIPfromFile(info_line);
	this->port = readPortfromFile(info_line);
	file.close();
}

// Checks if the port and ip gathered from the file are valid
bool ServerConnectionManager::isPortValid(const string& tmp_port) {
	// Ensure the port is only digits and within length limit
	if (tmp_port.length() > ProtocolConstants::MAX_PORT_LENGTH || tmp_port.find_first_not_of("0123456789") != std::string::npos) {
		return false;
	}
	int num_port = std::stoi(tmp_port);
	return num_port > ProtocolConstants::MIN_PORT_VALUE && num_port <= ProtocolConstants::MAX_PORT_VALUE;
}
bool ServerConnectionManager::isIPvalid(const string& tmp_ip) {
	try {
		boost::asio::ip::make_address(tmp_ip); // This will throw if the IP is invalid
		return true;
	}
	catch (...) {
		return false;
	}
}

// Reads the IP and Port from the file AFTER validaing it.
std::string ServerConnectionManager::readIPfromFile(const std::string& line) {
	size_t separator = line.find(':');
	return line.substr(0, separator);
}
std::string ServerConnectionManager::readPortfromFile(const std::string& line) {
	size_t separator = line.find(':');
	return line.substr(separator + 1);
}

// Validate the server.info file
std::string ServerConnectionManager::validate_server_file(std::ifstream& file) {
	std::string line;
	if (!std::getline(file, line) || file.peek() != EOF) {  // Ensure only 1 line exists
		throw std::runtime_error("Invalid or too many lines in server.info file");
	}

	// Split by ':'
	size_t separator = line.find(':');
	if (separator == std::string::npos) {
		throw std::runtime_error("no ':' found in server.info file");
	}

	std::string tmp_ip = line.substr(0, separator);
	std::string tmp_port = line.substr(separator + 1);

	if (!ServerConnectionManager::isIPvalid(tmp_ip) || !ServerConnectionManager::isPortValid(tmp_port)) {
		throw std::runtime_error("Invalid IP or Port in server.info file");
	}

	return line;
}

// Connects to the server and returns a smart pointer to the socket.
std::shared_ptr<tcp::socket> ServerConnectionManager::connectToServer() {
	if (!socket || !socket->is_open()) {
		try {
			boost::asio::ip::tcp::resolver resolver(io_context);
			boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(ip, port);

			socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
			boost::asio::connect(*socket, endpoints);
		}
		catch (const std::exception& e) {
			throw std::runtime_error("Failed to connect to server: " + std::string(e.what()));
		}
	}
	return socket;
}


//************************************************
/* Text Validation and Manipulation Functions*/
//************************************************

// Converts public key string to array.
std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> stringToArrayPubKey(const std::string& str) {
	std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> arr = {};  // Initialize with zeros
	std::memcpy(arr.data(), str.data(), std::min(str.size(), ProtocolConstants::PUBLIC_KEY_SIZE));  // Copy data
	return arr;
}

// Creates a random file name, between 8 and 32 characters long, with only ASCII characters
std::string createRandomFileName() {
	const std::string characters =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789-_";

	std::random_device rd;
	std::mt19937 gen(rd());

	// Randomize File Name Length (Between 8 and 32 characters)
	std::uniform_int_distribution<> lengthDist(ProtocolConstants::MIN_RANDOM_FILENAME_LENGTH, ProtocolConstants::MAX_RANDOM_FILENAME_LENGTH);
	size_t fileNameLength = lengthDist(gen);

	std::uniform_int_distribution<> charDist(0, characters.size() - 1);

	// Randomize File Name Characters - only ASCII
	std::string randomFileName;
	for (size_t i = 0; i < fileNameLength; ++i) {
		randomFileName += characters[charDist(gen)];
	}
	return randomFileName;
}

// Validates that a string contains ONLY ascii characters.
bool containsOnlyASCII(const std::string& name) {
	for (auto c : name) {
		if (static_cast<unsigned char>(c) > 127) {
			return false;
		}
	}
	return true;
}

// Validates a client name.
void validateClientName(const std::string& client_name) {
	// Ensure name length is within the valid range (1 to 254 characters)
	if (client_name.empty() || client_name.size() > 254) {
		throw std::runtime_error("Invalid client name: must be at least 1 character and up to 254 characters.");
	}
	// Ensure all characters are ASCII
	if (!containsOnlyASCII(client_name)) {
		throw std::runtime_error("Invalid client name: can't contain non-ASCII characters.");
	}
	return;
}

// Converts a 16 byte client id to ASCII representation, where every 2 characters represent an hex value with 8 bits.
std::string uuidToString_file(const std::array < uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& client_id) {
	std::stringstream ss;
	ss << std::hex << std::setfill('0'); // Format as hex with leading zeros

	for (size_t i = 0; i < client_id.size(); ++i) {
		ss << std::setw(2) << static_cast<int>(client_id[i]); // Print byte as hex
	}
	std::cout << std::dec;
	return ss.str();
}

// Converts a size 32 characters client id string, where each 2 characters are a 8-bit hex value to a 16 byte client id array of uint8_t
std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> stringToUUID_file(const std::string& client_id_string) {
	std::array<uint8_t, 16> uuid{};

	if (client_id_string.length() != 32) {  // Ensure it's exactly 16 bytes (32 hex characters)
		throw std::invalid_argument("Invalid UUID string length");
	}

	for (size_t i = 0; i < 16; ++i) {
		std::stringstream ss;
		ss << std::hex << client_id_string.substr(i * 2, 2); // Extract 2 characters
		int value;
		ss >> value;
		uuid[i] = static_cast<uint8_t>(value); // Convert hex to uint8_t
	}
	std::cout << std::dec;
	return uuid;
}

//************************************************
/* File Utility Functions for "me.info" file*/
//************************************************

// Function to validate the structure and data of me.info file 
void validateClientInfoFile(const std::string& filename) {
	try {
		std::ifstream file(filename);
		if (!file.is_open()) {
			throw std::runtime_error("Could not open file: " + filename);
		}

		std::vector<std::string> lines;
		std::string line;

		// Read all lines from the file
		while (std::getline(file, line)) {
			lines.push_back(line);
		}
		file.close();

		// Check structure (expected: at least 3 lines)
		if (lines.size() < 3) {
			throw std::runtime_error("File format is incorrect. Expected at least 3 lines.");
		}

		// Extract fields
		std::string username = lines[0];
		std::string client_id = lines[1];
		std::ostringstream private_key_oss;

		// Combine all remaining lines for private key
		for (size_t i = 2; i < lines.size(); ++i) {
			private_key_oss << lines[i];  // Preserve key as single line
		}
		std::string private_key = private_key_oss.str();

		// Validate client name in the file
		validateClientName(username);

		// Validate the client ID in the file.
		if (client_id.length() != 32) {
			throw std::runtime_error("Client ID must contain 32 characters, where each 2 characters are a valid 8bit hex value.");
		}
		for (char c : client_id) {
			if (!std::isxdigit(c)) {
				throw std::runtime_error("Client ID must contain 32 characters, where each 2 characters are a valid 8bit hex value.");
			}
		}

		// Validate that the private key is valid base64:
		std::regex base64_regex("^[A-Za-z0-9+/]+={0,2}$");
		if (!std::regex_match(private_key, base64_regex)) {
			throw std::runtime_error("Invalid base64 private key, contains non-base 64 characters.");
		}
	}
	catch (const std::exception& e) {
		throw std::runtime_error("Validation failed for me.info file (file may have been compromised) \n\t\t-> " + std::string(e.what()));
	}
}


// Creates a client.info file, and inserts the correct information according to the protocol standards.
bool CreateClientInfoFile(std::string filename, std::string username, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, std::string private_key_base64) {
	std::ofstream file(filename);
	if (!file.is_open()) {
		throw std::runtime_error("Failed to open file: " + filename);
	} 

	file << username << "\n";
	file << uuidToString_file(client_id) << "\n";
	file << private_key_base64 << "\n"; 

	file.close();
	return true;
}

// Reads the me.info file and returns the client id from the file.
std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> fetchClientIdFromFile() {
	try {
		validateClientInfoFile(ProtocolConstants::CLIENT_FILENAME);

		const std::string filename = ProtocolConstants::CLIENT_FILENAME;
		if (!doesFileExist(filename)) {
			throw std::runtime_error("me.info file doesn't exist. Please register to the server.");
		}

		std::ifstream file(filename);
		if (!file.is_open()) {
			throw std::runtime_error("Failed to open me.info");
		}

		std::string name;
		getline(file, name);

		std::string client_id_str;
		getline(file, client_id_str);

		file.close();
		return stringToUUID_file(client_id_str);
	}
	catch (const std::exception& e) {
		throw std::runtime_error("Failed to fetch client ID \n\t-> " + std::string(e.what()));
	}
}

// Returns the private key from the file (still in base 64)
std::string fetchPrivateKeyFromFile() {
	try {
		validateClientInfoFile(ProtocolConstants::CLIENT_FILENAME);

		std::ifstream file(ProtocolConstants::CLIENT_FILENAME);
		if (!file.is_open()) {
			throw std::runtime_error("Failed to open me.info");
		}
		std::string line;
		// Read and discard the username line
		std::getline(file, line);
		// Read and discard the client ID line
		std::getline(file, line);

		std::ostringstream oss;
		oss << file.rdbuf();

		file.close();
		return oss.str(); // Still in base 64
	}
	catch (const std::exception& e) {
		throw std::runtime_error("Failed to fetch private key \n\t-> " + std::string(e.what()));
	}
}

//********************************************
/* Utility Functions*/
//********************************************

// Asks the user for a client username, and return the client's ID.
std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> inputUsernameAndGetClientID() {
	std::string dest_client_name;
	std::cout << "Please enter client name: ";

	std::getline(std::cin, dest_client_name);

	validateClientName(dest_client_name);

	ClientHandler& handler = ClientHandler::getInstance();

	std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id = handler.getClientIDByName(dest_client_name); // Throws an error if the name isn't found.
	return client_id;
}


// Utility function that reads a fixed amount of bytes from the socket, validates that it read the correct amount of bytes, and then returns it as a vector.
std::vector<uint8_t> readFixedSize(boost::asio::ip::tcp::socket& socket, size_t size) {
	boost::asio::streambuf buffer;
	size_t bytes_read = boost::asio::read(socket, buffer.prepare(size));

	if (bytes_read < size) {
		throw std::runtime_error("Received data is too short. Expected " + std::to_string(size) + " bytes, got " + std::to_string(bytes_read));
	}

	buffer.commit(size);
	std::vector<uint8_t> data(size);
	std::istream input_stream(&buffer);
	input_stream.read(reinterpret_cast<char*>(data.data()), size);

	return data;
}

// "Flushes" the buffer given to it as a parameter (consumes and clears it basically)
void flushBuffer(boost::asio::streambuf& buffer, std::istream& stream) {
	std::string temp;
	while (buffer.size() > 0) {
		std::getline(stream, temp); // Consume and discard data
	}

	// Reset buffer and input stream state
	buffer.consume(buffer.size());
	stream.clear();
	//std::cout << "Flushed remaining data from buffer and reset stream state.\n"; TODO maybe delete this???
}

// Checks if a file exists using the filename
bool doesFileExist(const std::string& filename) {
	if (filesystem::exists(filename)) {
		return true;
	}
	else {
		return false;
	}
}


//********************************************
/* Main Client Logic Functions*/
//********************************************

// Parses the response coming back from the server according to the protocol, using the readFixedSize function.
std::unique_ptr<BaseResponse> parseResponse(std::shared_ptr<tcp::socket>& socket) {
	boost::asio::streambuf buffer; // Declare a buffer for the incoming socket bytes, for easy parsing.
	std::istream input_stream(&buffer); // Linked to the buffer, used for easy gathering of the required data
	ClientHandler& handler = ClientHandler::getInstance(); // Access the singleton global ClientHandler instance, for use in the entire parsing logic.
	try {
		// Read the full response header at once
		std::vector<uint8_t> header_data = readFixedSize(*socket, ProtocolConstants::RESPONSE_HEADER_SIZE);

		uint8_t version;
		uint16_t response_code;
		uint32_t payload_size;

		// Extract fields from the header_data
		std::memcpy(&version, header_data.data(), ProtocolConstants::VERSION_SIZE);
		std::memcpy(&response_code, header_data.data() + ProtocolConstants::VERSION_SIZE, ProtocolConstants::RESPONSE_CODE_SIZE);
		std::memcpy(&payload_size, header_data.data() + ProtocolConstants::VERSION_SIZE + ProtocolConstants::RESPONSE_CODE_SIZE, ProtocolConstants::PAYLOAD_FIELD_SIZE);

		// Convert to native endian format if needed
		boost::endian::little_to_native_inplace(response_code);
		boost::endian::little_to_native_inplace(payload_size);

		if (response_code == ProtocolConstants::Response::REGISTRATION_SUCCESS) {
			if (payload_size != ProtocolConstants::CLIENT_ID_SIZE) {
				throw std::runtime_error("Payload size has different value than what's expected in register response");
			}

			std::vector<uint8_t> client_id_vec = readFixedSize(*socket, ProtocolConstants::CLIENT_ID_SIZE);

			// Convert vector to array
			std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
			std::copy_n(client_id_vec.begin(), ProtocolConstants::CLIENT_ID_SIZE, client_id.begin());

			socket->close();
			return std::make_unique<RegisterResponse>(version, response_code, payload_size, client_id);
		}
		else if (response_code == ProtocolConstants::Response::CLIENT_LIST_FETCH_SUCCESS) {
			size_t num_of_clients = payload_size / (ProtocolConstants::CLIENT_ID_SIZE + ProtocolConstants::CLIENT_NAME_SIZE);

			if (num_of_clients > 0) {
				std::cout << "Client list request is successful.\n";
				std::cout << "\nPrinting Client Names (" << num_of_clients << " total): " << endl;

				for (size_t i = 0; i < num_of_clients; i++) {
					// Read client ID and convert vector -> array
					std::vector<uint8_t> client_id_vec = readFixedSize(*socket, ProtocolConstants::CLIENT_ID_SIZE);
					std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
					std::copy_n(client_id_vec.begin(), ProtocolConstants::CLIENT_ID_SIZE, client_id.begin());

					// Read client name and convert vector -> string
					std::vector<uint8_t> client_name_vec = readFixedSize(*socket, ProtocolConstants::CLIENT_NAME_SIZE);
					std::string client_name(client_name_vec.begin(), client_name_vec.end());

					// Trim null terminators (if any)
					client_name.erase(std::find(client_name.begin(), client_name.end(), '\0'), client_name.end());

					handler.addClient(handler.arrayToStringID(client_id), client_name);
					cout << i + 1 << ". " << client_name << endl;
				}
			}
			else { // 0 clients
				std::cout << "\nThere are no other clients registered to the server.\n";
			}
			socket->close();
			return std::make_unique<ClientsListResponse>(version, response_code, payload_size);
		}
		else if (response_code == ProtocolConstants::Response::PUBLIC_KEY_FETCH_SUCCESS) {
			if (payload_size != ProtocolConstants::CLIENT_ID_SIZE + ProtocolConstants::PUBLIC_KEY_SIZE) {
				throw std::runtime_error("Payload size has different value than what's expected in public key response");
			}
			// Read client id and convert vec -> array
			std::vector<uint8_t> client_id_vec = readFixedSize(*socket, ProtocolConstants::CLIENT_ID_SIZE);
			std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
			std::copy_n(client_id_vec.begin(), ProtocolConstants::CLIENT_ID_SIZE, client_id.begin());

			// Read public key and convert vec -> array
			std::vector<uint8_t> pubkey_vec = readFixedSize(*socket, ProtocolConstants::PUBLIC_KEY_SIZE);
			std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> public_key;
			std::copy_n(pubkey_vec.begin(), ProtocolConstants::PUBLIC_KEY_SIZE, public_key.begin());

			handler.setPublicKey(handler.arrayToStringID(client_id), public_key);
			socket->close();
			std::cout << "\nPublic key of " << handler.getClient(handler.arrayToStringID(client_id))->client_name << " was fetched from the server and saved.\n";
			return std::make_unique<PublicKeyResponse>(version, response_code, payload_size, client_id, public_key);
		}
		else if (response_code == ProtocolConstants::Response::MESSAGE_SENT_SUCCESS) {
			if (payload_size != ProtocolConstants::CLIENT_ID_SIZE + ProtocolConstants::MESSAGE_ID_SIZE) {
				throw std::runtime_error("Payload size has different value than what's expected in message sent response");
			}
			// Read client id and convert vec -> array
			std::vector<uint8_t> client_id_vec = readFixedSize(*socket, ProtocolConstants::CLIENT_ID_SIZE);
			std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
			std::copy_n(client_id_vec.begin(), ProtocolConstants::CLIENT_ID_SIZE, client_id.begin());

			// Read message id and convert vec -> uint32_t
			std::vector<uint8_t> message_id_vec = readFixedSize(*socket, ProtocolConstants::MESSAGE_ID_SIZE);
			uint32_t message_id;
			std::memcpy(&message_id, message_id_vec.data(), ProtocolConstants::MESSAGE_ID_SIZE);

			boost::endian::little_to_native_inplace(message_id);

			socket->close();
			return std::make_unique<MessageSentResponse>(version, response_code, payload_size, client_id, message_id);
		}
		else if (response_code == ProtocolConstants::Response::FETCHING_INCOMING_MESSAGES_SUCCESS) {
			if (payload_size == 0) {
				std::cout << "There are no messages waiting for you in the server.\n";
				socket->close();
				return std::make_unique<WaitingMessagesFetchResponse>(version, response_code, payload_size);
			}
			std::cout << "\nYour messages were fetched from the server. Printing the incoming messages: \n" << endl;
			while (payload_size > 0) {
				// Read the fixed-size message header
				std::vector<uint8_t> header_data = readFixedSize(*socket, ProtocolConstants::MESSAGE_RESPONSE_HEADER_SIZE);
				payload_size -= ProtocolConstants::MESSAGE_RESPONSE_HEADER_SIZE;
				
				std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
				uint32_t message_id;
				uint8_t message_type;
				uint32_t message_content_size;

				std::memcpy(client_id.data(), header_data.data(), ProtocolConstants::CLIENT_ID_SIZE);
				std::memcpy(&message_id, header_data.data() + ProtocolConstants::CLIENT_ID_SIZE, ProtocolConstants::MESSAGE_ID_SIZE);
				std::memcpy(&message_type, header_data.data() + ProtocolConstants::CLIENT_ID_SIZE + ProtocolConstants::MESSAGE_ID_SIZE, ProtocolConstants::MESSAGE_TYPE_SIZE);
				std::memcpy(&message_content_size, header_data.data() + ProtocolConstants::CLIENT_ID_SIZE + ProtocolConstants::MESSAGE_ID_SIZE + ProtocolConstants::MESSAGE_TYPE_SIZE, ProtocolConstants::MESSAGE_CONTENT_FIELD_SIZE);

				boost::endian::little_to_native_inplace(message_id);
				boost::endian::little_to_native_inplace(message_type);
				boost::endian::little_to_native_inplace(message_content_size);

				// Read the message content from the communication
				std::vector<uint8_t> message_content = readFixedSize(*socket, message_content_size);
				payload_size -= message_content_size;

				// Checking if we have the client name in our client list.
				auto client_opt = handler.getClient(handler.arrayToStringID(client_id));
				// Printing the message
				std::cout << "From: ";
				if (client_opt.has_value()) {
					std::cout << client_opt->client_name << std::endl;
				}
				else {
					std::cerr << "\nWARNING: Client ID not found in the clients list. Can't print sender name.\nMake sure to ask for an updated clients list!\n";
				}
				std::cout << "Content: " << endl;

				if (message_type == ProtocolConstants::Message::REQUEST_SYMMETRICAL_KEY) {
					std::cout << "Request For Symmetric Key" << endl;
					if (client_opt.has_value()) { // If the client ID is in the clients list, set his "symmetric_key_requested" to true.
						handler.setSymmetricKeyRequestedToTrue(handler.arrayToStringID(client_id));
					}
				}
				else if (message_type == ProtocolConstants::Message::SEND_SYMMETRICAL_KEY) {
					std::cout << "Symmetric Key Received" << endl;
					try {
						// Copying the vector which contains an encrypted symmetric key into a string
						std::string encryptedSymmetricKey(message_content.begin(), message_content.end());

						if (encryptedSymmetricKey.size() != message_content_size) {
							std::cerr << "ERROR: Encrypted key size mismatch! Expected "<< message_content_size << " bytes, got " << encryptedSymmetricKey.size() << std::endl;
						}

						// Gathering the decoded private key and creating a decryptor.
						std::string decoded_priv_key = Base64Wrapper::decode(fetchPrivateKeyFromFile());
						RSAPrivateWrapper rsaDecryptor(decoded_priv_key);

						// Decrypting the symmetric key
						std::string decryptedSymmetricKey = rsaDecryptor.decrypt(encryptedSymmetricKey);

						// Copying the string into an array of uint8_t
						std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE> symmetric_key = {};  // Zero-initialize
						std::copy_n(decryptedSymmetricKey.begin(), std::min(decryptedSymmetricKey.size(), ProtocolConstants::SYMMETRIC_KEY_SIZE), symmetric_key.begin());

						// Saves the symmetric key for this client.
						handler.setSymmetricKey(handler.arrayToStringID(client_id), symmetric_key);
					}
					catch (const CryptoPP::Exception& e) {
						std::cerr << "RSA decryption of symmetric key failed: " << e.what() << std::endl;
						continue;
					}
					catch (const std::exception& e) {
						std::cerr << "Unexpected error: " << e.what() << std::endl;
						continue;
					}
				}
				else if (message_type == ProtocolConstants::Message::SEND_TEXT_MESSAGE) {
					if ((handler.getClient(handler.arrayToStringID(client_id))->symmetric_key).has_value()) {
						try {
							// Using the symmetric key to decrypt the text message.
							std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE> symmetric_key_arr = handler.getClient(handler.arrayToStringID(client_id))->symmetric_key.value();

							AESWrapper aes(symmetric_key_arr.data(), ProtocolConstants::SYMMETRIC_KEY_SIZE);

							std::string message_content_string(message_content.begin(), message_content.end());

							std::string decrypted_text = aes.decrypt(message_content_string.c_str(), message_content_string.length());

							std::cout << decrypted_text << endl; 
						} catch (const CryptoPP::Exception& e) {
							std::cout << "Can't decrypt message.\n";
							continue;  // Skip to the next iteration if decryption fails
						} catch (const std::exception& e) {
							std::cerr << "Unexpected error: " << e.what() << std::endl;
							continue;
						}
					}
					else {
						std::cout << "Can't decrypt message.\n";
					}
				}
				else if (message_type == ProtocolConstants::Message::SEND_FILE_MESSAGE) {
					if ((handler.getClient(handler.arrayToStringID(client_id))->symmetric_key).has_value()) {
						try {
							// Using the symmetric key to decrypt the file content.
							std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE> symmetric_key_arr = handler.getClient(handler.arrayToStringID(client_id))->symmetric_key.value();
							AESWrapper aes(symmetric_key_arr.data(), ProtocolConstants::SYMMETRIC_KEY_SIZE);
							std::string file_content_string(message_content.begin(), message_content.end());
							std::string decrypted_file_content = aes.decrypt(file_content_string.c_str(), file_content_string.length());

							// Finding %TMP% folder, creating a random file name(NO extension, since it wasn't specified) with a random length between 8-32 chars.
							// Then - creating the full path.
							std::filesystem::path temp_folder_path = std::filesystem::temp_directory_path();
							std::string random_file_name = createRandomFileName();
							std::filesystem::path random_file_path = temp_folder_path / random_file_name;

							std::string full_path = random_file_path.string();
							// Attempting to create the file and read
							std::ofstream file(full_path, std::ios::binary);
							if (!file) {
								std::cerr << "Received a file, but could not create temp file and save it." << std::endl;
								continue;
							}
							file << decrypted_file_content;
							file.close();
							std::cout << "Received a file, the full path is: \n" << full_path << "\n";
						}catch (const CryptoPP::Exception& e) {
							std::cout << "Can't decrypt file content.\n";
							continue;
						}catch (const std::exception& e) {
							std::cerr << "Unexpected error: " << e.what() << std::endl;
							continue;
						}
					}
					else {
						std::cout << "Can't decrypt file content.\n";
					}
				}
				std::cout << "-----<EOM>-----" << endl;
				std::cout << "\n" << endl;
			}
			socket->close();
			return std::make_unique<WaitingMessagesFetchResponse>(version, response_code, payload_size);
		}
		else if (response_code == ProtocolConstants::Response::GENERAL_ERROR)
		{
			socket->close();
			std::cout << "\nServer responded with an error." << endl;
			return std::make_unique<ErrorResponse>(version, response_code, payload_size);
		}
		else {
			flushBuffer(buffer, input_stream);
			socket->close();
			throw std::runtime_error("Received an unidentified response code");
		}
	}
	catch(const std::exception& e){
		std::cerr << "Error handling server response: " << e.what() << "\n";
	}
}

// Handles the logic to register a client to the server
void handleClientRegister(std::unique_ptr<BaseRequest>& request, std::unique_ptr<BaseResponse>& response,ServerConnectionManager& serverConnection) {
	const string filename = ProtocolConstants::CLIENT_FILENAME;
	if (doesFileExist(filename)) {
		throw std::runtime_error("me.info file already exists, cancelling register operation.");
	}

	string username;
	std::cout << "Please enter your new username (up to 254 valid ASCII characters):" << endl;
	std::getline(std::cin, username);

	validateClientName(username);

	// Creating a default client_id, filled with AA hexa bytes.
	std::array<uint8_t, 16> default_uuid;
	default_uuid.fill(0xAA);

	// Creating the private and public keys
	RSAPrivateWrapper rsapriv;
	std::string pubkey_str = rsapriv.getPublicKey(); // Creating the public key from the private key
	std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pubkey_arr = stringToArrayPubKey(pubkey_str);
	std::string priv_base64key = Base64Wrapper::encode(rsapriv.getPrivateKey()); // Converting the public key to base 64

	// Creating the request
	request = make_unique<RegisterRequest>(
		default_uuid,
		ProtocolConstants::CLIENT_VERSION,
		ProtocolConstants::Request::REGISTER_REQUEST,
		ProtocolConstants::REGISTER_PAYLOAD_SIZE,
		username,
		pubkey_arr
	);

	auto socket = serverConnection.connectToServer();

	// Send the registration request
	request->sendRequest(socket);

	std::cout << "Sending a register request to the server with the username: " << username << endl;

	// Receive a response
	response = parseResponse(socket);

	// Getting the client_id from the RegisterResponse class
	if (auto* regResponse = dynamic_cast<RegisterResponse*>(response.get())) {
		std::cout << "Register operation is successful.\n";
		auto clientID = regResponse->getClientID();
		CreateClientInfoFile(filename, username, clientID, priv_base64key);

		std::cout << "Your client details are saved in me.info file.\n\nMake sure to ask for a clients list before making any requests." << endl;
	}
}

// Handles the logic to make a clients list request
void handleClientsListAndFetchMessagesRequest(int operation_code, std::unique_ptr<BaseRequest>& request, std::unique_ptr<BaseResponse>& response, ServerConnectionManager& serverConnection) {
	std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
	client_id = fetchClientIdFromFile();

	if (operation_code == ProtocolConstants::Input_Codes::CLIENTS_LIST) {
		std::cout << "Sending a request to fetch the registered clients list from the server...\n";
		request = make_unique<basicRequest>(
			client_id,
			ProtocolConstants::CLIENT_VERSION,
			ProtocolConstants::Request::CLIENTS_LIST_REQUEST,
			ProtocolConstants::CLIENT_LIST_AND_FETCH_MESSAGES_PAYLOAD_SIZE
		);
	}
	else if (operation_code == ProtocolConstants::Input_Codes::FETCH_WAITING_MESSAGES) {
		std::cout << "Sending a request to fetch your messages from the server...\n";
		request = make_unique<basicRequest>(
			client_id,
			ProtocolConstants::CLIENT_VERSION,
			ProtocolConstants::Request::FETCH_WAITING_MESSAGES_REQUEST,
			ProtocolConstants::CLIENT_LIST_AND_FETCH_MESSAGES_PAYLOAD_SIZE
		);
	}
	auto socket = serverConnection.connectToServer();
	request->sendRequest(socket);

	// Managing the response
	response = parseResponse(socket);
}

// Handles the public key request
void handlePublicKeyRequest(std::unique_ptr<BaseRequest>& request, std::unique_ptr<BaseResponse>& response, ServerConnectionManager& serverConnection) {
	std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
	client_id = fetchClientIdFromFile();

	std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> dest_client_id = inputUsernameAndGetClientID();

	ClientHandler& handler = ClientHandler::getInstance();

	std::string client_name = handler.getClient(handler.arrayToStringID(dest_client_id))->client_name;

	if (!(handler.getClient(handler.arrayToStringID(dest_client_id))->public_key).has_value()) {
		std::cout << "Sending a request to fetch " << client_name << "\'s public key from the server...\n";
		request = make_unique<PublicKeyRequest>(
			client_id,
			ProtocolConstants::CLIENT_VERSION,
			ProtocolConstants::Request::FETCH_OTHER_CLIENT_PUBLIC_KEY_REQUEST,
			ProtocolConstants::PUBLIC_KEY_FETCH_PAYLOAD_SIZE,
			dest_client_id
		);
		auto socket = serverConnection.connectToServer();
		request->sendRequest(socket);

		// Managing the response
		response = parseResponse(socket);
	}
	else {
		std::cout << "\nYou've already requested for the public key of " << client_name << endl;
	}
}

// Handles the 4 types of message types sending and response.
void handleMessageSend(int operation_code, std::unique_ptr<BaseRequest>& request, std::unique_ptr<BaseResponse>& response, ServerConnectionManager& serverConnection) {
	ClientHandler& handler = ClientHandler::getInstance();
	
	std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
	client_id = fetchClientIdFromFile();

	std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> dest_client_id = inputUsernameAndGetClientID();

	std::string dest_client_name = handler.getClient(handler.arrayToStringID(dest_client_id))->client_name;

	if (operation_code == ProtocolConstants::Input_Codes::REQUEST_SYMMETRIC_KEY) {
		request = make_unique<symmetricKeyRequestMessage>(
			client_id,
			ProtocolConstants::CLIENT_VERSION,
			ProtocolConstants::Request::SEND_MESSAGE,
			ProtocolConstants::MESSAGE_REQUEST_HEADER_SIZE,
			dest_client_id,
			ProtocolConstants::Message::REQUEST_SYMMETRICAL_KEY,
			ProtocolConstants::MESSAGE_REQUEST_SYMMETRICAL_KEY_SIZE
		);
		std::cout << "\nSymmetric key request message sent to " << dest_client_name << ".\n";
	}
	else if (operation_code == ProtocolConstants::Input_Codes::SEND_SYMMETRIC_KEY) {
		if (handler.getClient(handler.arrayToStringID(dest_client_id))->symmetric_key_requested == true) {
			// Generating a symmetric key (if there isn't one)
			if (!(handler.getClient(handler.arrayToStringID(dest_client_id))->symmetric_key).has_value()) {
				unsigned char symmetric_key[ProtocolConstants::SYMMETRIC_KEY_SIZE] = {};
				AESWrapper aes(AESWrapper::GenerateKey(symmetric_key, ProtocolConstants::SYMMETRIC_KEY_SIZE), ProtocolConstants::SYMMETRIC_KEY_SIZE);

				// Encrypting the symmetric key using the destination client's public key
				if ((handler.getClient(handler.arrayToStringID(dest_client_id))->public_key).has_value()) {
					std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> dest_pub_key = (handler.getClient(handler.arrayToStringID(dest_client_id))->public_key).value();
					std::string dest_pub_key_str(dest_pub_key.begin(), dest_pub_key.end());

					RSAPublicWrapper rsapub(dest_pub_key_str);
					std::string encrypted_symmetric_key = rsapub.encrypt((const char*)symmetric_key, sizeof(symmetric_key));

					// Copying the char[] array symmetric key into uint8_t array for easy sending and storage.
					std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE> symm_key_arr;
					std::copy(std::begin(symmetric_key), std::end(symmetric_key), symm_key_arr.begin());

					handler.setSymmetricKey(handler.arrayToStringID(dest_client_id), symm_key_arr); // Setting the symmetric key for the target client

					request = make_unique<symmetricKeySendMessage>(
						client_id,
						ProtocolConstants::CLIENT_VERSION,
						ProtocolConstants::Request::SEND_MESSAGE,
						ProtocolConstants::MESSAGE_REQUEST_HEADER_SIZE + encrypted_symmetric_key.size(),
						dest_client_id,
						ProtocolConstants::Message::SEND_SYMMETRICAL_KEY,
						encrypted_symmetric_key.size(),
						encrypted_symmetric_key
					);
					std::cout << "\nYour shared symmetric key was sent to " << dest_client_name << ".\n";
				}
				else {
					std::cout << "\nYou must send a request for " << dest_client_name << "\'s public key before attempting to send them a symmetric key.\n";
					return;
				}
			}
			else {
				std::cout << "\nYou already have a shared symmetric key with " << dest_client_name <<".\n";
				return;
			}
		}
		else {
			std::cout << "\nYou can't send a symmetric key to \"" << dest_client_name << "\" until they request one from you.\n";
			std::cout << "However, you can send them a request for a symmetric key.\n";
			return;
		}
	}
	else if (operation_code == ProtocolConstants::Input_Codes::SEND_TEXT_MESSAGE_CODE) {
		if ((handler.getClient(handler.arrayToStringID(dest_client_id))->symmetric_key).has_value()) { // If there is a symmetric key with the other client
			std::string text_input;
			std::cout << "Please enter the required text message to send: \n";
			std::getline(std::cin, text_input);

			// Truncate it to fit the correct size that can be represented by 4 bytes = (2^32 bytes - message header size) IF it's bigger than this.
			if (text_input.length() > ProtocolConstants::MAXIMUM_TEXT_AND_FILE_SIZE) {
				std::cout << "Input is too big to fit (more than 2^32 -1 characters). Truncating it to fit.\n";
				text_input = text_input.substr(0, ProtocolConstants::MAXIMUM_TEXT_AND_FILE_SIZE);
			}

			// Using the symmetric key to encrypt the text message.
			std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE> symmetric_key_arr = handler.getClient(handler.arrayToStringID(dest_client_id))->symmetric_key.value();

			AESWrapper aes(symmetric_key_arr.data(), ProtocolConstants::SYMMETRIC_KEY_SIZE);
			std::string ciphertext = aes.encrypt(text_input.c_str(), text_input.length());

			std::vector<uint8_t> vec_encrypted_text(ciphertext.begin(), ciphertext.end());

			request = make_unique<textMessage>(
				client_id,
				ProtocolConstants::CLIENT_VERSION,
				ProtocolConstants::Request::SEND_MESSAGE,
				ProtocolConstants::MESSAGE_REQUEST_HEADER_SIZE + vec_encrypted_text.size(),
				dest_client_id,
				ProtocolConstants::Message::SEND_TEXT_MESSAGE,
				vec_encrypted_text.size(),
				vec_encrypted_text
			);
			std::cout << "\nYour encrypted text message was sent to " << dest_client_name << ".\n";
		}
		else {
			std::cout << "\nYou need a shared symmetric key with " << dest_client_name << " to send them a text message.\n";
			return;
		}
	}
	else if(operation_code == ProtocolConstants::Input_Codes::SEND_FILE){ 
		if ((handler.getClient(handler.arrayToStringID(dest_client_id))->symmetric_key).has_value()) { // If there is a symmetric key with another client
			std::string file_path;
			std::cout << "Please enter the full path to the file you want to send (ASCII only path): \n";
			std::getline(std::cin, file_path);

			// Validating the file name and file content.
			if (!containsOnlyASCII(file_path)) {
				throw runtime_error("File path contains non-ASCII characters. Cancelling file send operation.");
			}
			if (!doesFileExist(file_path)) {
				throw runtime_error("File not found");
			}
			std::ifstream file(file_path, std::ios::binary);
			if (!file.is_open()) {
				throw std::runtime_error("File not found");
			}
			if (file.peek() == std::ifstream::traits_type::eof()) {
				throw std::runtime_error("File is empty. Cancelling file send operation.");
			}

			// Copying the entire file content into a string
			std::stringstream buffer;
			buffer << file.rdbuf();
			std::string file_content = buffer.str();
			file.close();

			// Don't send the file if it's bigger than 4 bytes = (2^32 - message header size) bytes, because a partial file can be corrupted.
			if (file_content.length() > ProtocolConstants::MAXIMUM_TEXT_AND_FILE_SIZE) {
				std::cout << "File is too big to fit (more than 2^32 -1 characters). Cancelling file send request\n";
				return;
			}

			// Using the symmetric key to encrypt the text message.
			std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE> symmetric_key_arr = handler.getClient(handler.arrayToStringID(dest_client_id))->symmetric_key.value();
			AESWrapper aes(symmetric_key_arr.data(), ProtocolConstants::SYMMETRIC_KEY_SIZE);
			std::string ciphertext = aes.encrypt(file_content.c_str(), file_content.length());

			std::vector<uint8_t> vec_encrypted_file(ciphertext.begin(), ciphertext.end());

			request = make_unique<FileSendMessage>(
				client_id,
				ProtocolConstants::CLIENT_VERSION,
				ProtocolConstants::Request::SEND_MESSAGE,
				ProtocolConstants::MESSAGE_REQUEST_HEADER_SIZE + vec_encrypted_file.size(),
				dest_client_id,
				ProtocolConstants::Message::SEND_FILE_MESSAGE,
				vec_encrypted_file.size(),
				vec_encrypted_file
			);
			std::cout << "Your encrypted file was sent to " << dest_client_name << ".\n";
		}
		else {
			std::cout << "You need a shared symmetric key with " << dest_client_name << " to them send a file.\n";
			return;
		}
	}
	auto socket = serverConnection.connectToServer();
	request->sendRequest(socket);
	// Managing the response
	response = parseResponse(socket);
}

// Handles the user input, by calling the handle request function (respective to the relevant request)
void handleUserInput(int operation_code, ServerConnectionManager& serverConnection) {
	try {
		std::unique_ptr<BaseRequest> request;
		std::unique_ptr<BaseResponse> response;
		ClientHandler& handler = ClientHandler::getInstance();

		std::cout << "\n";
		if (!doesFileExist(ProtocolConstants::CLIENT_FILENAME) && operation_code != ProtocolConstants::Input_Codes::REGISTER) {
			std::cout << "You must register to the server before making any requests.\n";
			return; // Don't let the user make ANY other request then register, if he's not registered.
		}
		// Don't let the user make any requests if the clients list is empty. Encouraging the user to ask for a clients list.
		if (handler.numOfClients() == 0 && (operation_code != ProtocolConstants::Input_Codes::REGISTER && operation_code != ProtocolConstants::Input_Codes::CLIENTS_LIST)) {
			std::cout << "You must ask for a clients list before making requests concerning other clients (requests 130 - 153).\n";
			return;
		}
		// Call the different operations based on the request code.
		if (operation_code == ProtocolConstants::Input_Codes::REGISTER){
			handleClientRegister(request, response,serverConnection);
		}
		else if (operation_code == ProtocolConstants::Input_Codes::CLIENTS_LIST){
			handleClientsListAndFetchMessagesRequest(operation_code, request, response, serverConnection);
		}
		else if (operation_code == ProtocolConstants::Input_Codes::FETCH_OTHER_CLIENT_PUBLIC_KEY){
			handlePublicKeyRequest(request, response, serverConnection);
		}
		else if (operation_code == ProtocolConstants::Input_Codes::FETCH_WAITING_MESSAGES){
			handleClientsListAndFetchMessagesRequest(operation_code, request, response, serverConnection);
		}
		else if (operation_code == ProtocolConstants::Input_Codes::SEND_TEXT_MESSAGE_CODE || operation_code == ProtocolConstants::Input_Codes::SEND_FILE
			|| operation_code == ProtocolConstants::Input_Codes::SEND_SYMMETRIC_KEY || operation_code == ProtocolConstants::Input_Codes::REQUEST_SYMMETRIC_KEY)
		{
			handleMessageSend(operation_code, request, response, serverConnection);
		}
		else {
			std::cout << "Please enter one of the valid options.\n";
		}
	}
	catch (const std::exception& e) {
		std::cerr << "Error while handling request: " << e.what() << "\n";
	}
	return;
}

/* Main Function - main loop*/
int main() {
	ServerConnectionManager serverConnection;
	try {
		while (true) {
			int responseCode;
			std::cout << "MessageU client at your service.\n" << endl;
			std::cout << "110) Register\n120) Request for clients list\n130) Request for public key\n140) Request for waiting messages" << endl;
			std::cout << "150) Send a text message\n151) Send a request for symmetric key\n152) Send your symmetric key\n153) Send a file\n0) Exit client\n?" << endl;
			if (cin >> responseCode) {
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear newline

				if (responseCode == ProtocolConstants::Input_Codes::EXIT_CLIENT) {
					std::cout << "\nThanks for using MessageU!" << endl;
					break;
				}
				else { // User inputted a number that isn't 0.
					handleUserInput(responseCode, serverConnection);
				}
			}
			else { //Non numberical input, clear the input stream!
				std::cout << "Non-numerical input detected. Please enter one of the valid options.\n";
				cin.clear();
				cin.ignore(numeric_limits<streamsize>::max(), '\n');
			}
			std::cout << "\n-----------------------------------------------------" << endl;
		}
	}
	catch (const std::exception& e) {
		std::cerr << "Client Error: " << e.what() << "\n";
	}
	return 0;
}




/*
*	Wrapper Function and Classes Provided externally, for use with the project's demands.
*/

// RSA Wrappers
RSAPublicWrapper::RSAPublicWrapper(const char* key, unsigned int length)
{
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(key), length, true);
	_publicKey.Load(ss);
}

RSAPublicWrapper::RSAPublicWrapper(const std::string& key)
{
	CryptoPP::StringSource ss(key, true);
	_publicKey.Load(ss);
}

RSAPublicWrapper::~RSAPublicWrapper()
{
}

std::string RSAPublicWrapper::getPublicKey() const
{
	std::string key;
	CryptoPP::StringSink ss(key);
	_publicKey.Save(ss);
	return key;
}

char* RSAPublicWrapper::getPublicKey(char* keyout, unsigned int length) const
{
	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	_publicKey.Save(as);
	return keyout;
}

std::string RSAPublicWrapper::encrypt(const std::string& plain)
{
	std::string cipher;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
	CryptoPP::StringSource ss(plain, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}

std::string RSAPublicWrapper::encrypt(const char* plain, unsigned int length)
{
	std::string cipher;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(plain), length, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}



RSAPrivateWrapper::RSAPrivateWrapper()
{
	_privateKey.Initialize(_rng, BITS);
}

RSAPrivateWrapper::RSAPrivateWrapper(const char* key, unsigned int length)
{
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(key), length, true);
	_privateKey.Load(ss);
}

RSAPrivateWrapper::RSAPrivateWrapper(const std::string& key)
{
	CryptoPP::StringSource ss(key, true);
	_privateKey.Load(ss);
}

RSAPrivateWrapper::~RSAPrivateWrapper()
{
}

std::string RSAPrivateWrapper::getPrivateKey() const
{
	std::string key;
	CryptoPP::StringSink ss(key);
	_privateKey.Save(ss);
	return key;
}

char* RSAPrivateWrapper::getPrivateKey(char* keyout, unsigned int length) const
{
	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	_privateKey.Save(as);
	return keyout;
}

std::string RSAPrivateWrapper::getPublicKey() const
{
	CryptoPP::RSAFunction publicKey(_privateKey);
	std::string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	return key;
}

char* RSAPrivateWrapper::getPublicKey(char* keyout, unsigned int length) const
{
	CryptoPP::RSAFunction publicKey(_privateKey);
	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	publicKey.Save(as);
	return keyout;
}

std::string RSAPrivateWrapper::decrypt(const std::string& cipher)
{
	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(cipher, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}

std::string RSAPrivateWrapper::decrypt(const char* cipher, unsigned int length)
{
	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(reinterpret_cast<const CryptoPP::byte*>(cipher), length, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}


// Base64 Wrapper
std::string Base64Wrapper::encode(const std::string& str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		) // Base64Encoder
	); // StringSource

	return encoded;
}

std::string Base64Wrapper::decode(const std::string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}


// AES Wrapper:

unsigned char* AESWrapper::GenerateKey(unsigned char* buffer, unsigned int length)
{
	for (size_t i = 0; i < length; i += sizeof(unsigned int))
		_rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
	return buffer;
}

AESWrapper::AESWrapper()
{
	GenerateKey(_key, DEFAULT_KEYLENGTH);
}

AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	if (length != DEFAULT_KEYLENGTH)
		throw std::length_error("key length must be 16 bytes");
	memcpy_s(_key, DEFAULT_KEYLENGTH, key, length);
}

AESWrapper::~AESWrapper()
{
}

const unsigned char* AESWrapper::getKey() const
{
	return _key;
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}


std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}
