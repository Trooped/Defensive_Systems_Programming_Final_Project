/*
	ADD DOCUMENTATION

*/


#include "client.hpp"

using namespace std;
using boost::asio::ip::tcp;

//Constructors for Request & Message classes and inheriting classes.
BaseRequest::BaseRequest(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size)
	: client_id{ client_id }, version{ version }, request_code{ request_code }, payload_size{ payload_size } { }

void BaseRequest::sendRequest(tcp::socket& socket) const {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);
	request_stream.write(reinterpret_cast<const char*>(&request_code), sizeof(request_code));
	request_stream.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));
	
	boost::asio::write(socket, buffer);
}

RegisterRequest::RegisterRequest(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string client_name, std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> public_key)
	: BaseRequest(client_id, version, request_code, payload_size), client_name(client_name), public_key(public_key) { }

/*
std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> RegisterRequest::stringToArray(const std::string& str) {
	std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> arr = {};  // Initialize with zeros
	std::memcpy(arr.data(), str.data(), std::min(str.size(), ProtocolConstants::PUBLIC_KEY_SIZE));  // Copy data
	return arr;
}
*/
void RegisterRequest::sendRequest(tcp::socket& socket) {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);
	request_stream.write(reinterpret_cast<const char*>(&request_code), sizeof(request_code));
	request_stream.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

	while (client_name.length() < 255) {
		client_name += '\0';
	}
	const char* char_name = client_name.c_str();
	request_stream.write(reinterpret_cast<const char*>(&char_name), sizeof(char_name));

	request_stream.write(reinterpret_cast<const char*>(public_key.data()), public_key.size());

	boost::asio::write(socket, buffer);
}


basicRequest::basicRequest(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size)
	: BaseRequest(client_id, version, request_code, payload_size) { }
void basicRequest::sendRequest(tcp::socket& socket) {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);
	request_stream.write(reinterpret_cast<const char*>(&request_code), sizeof(request_code));
	request_stream.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

	boost::asio::write(socket, buffer);
}

PublicKeyRequest::PublicKeyRequest(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id)
	: BaseRequest(client_id, version, request_code, payload_size), target_client_id(target_client_id) { }
void PublicKeyRequest::sendRequest(tcp::socket& socket) {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);
	request_stream.write(reinterpret_cast<const char*>(&request_code), sizeof(request_code));
	request_stream.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), target_client_id.size());

	boost::asio::write(socket, buffer);
}


Message::Message(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size)
	: BaseRequest(client_id, version, request_code, payload_size), target_client_id(target_client_id), message_type(message_type), message_content_size(message_content_size) { }
void Message::sendRequest(tcp::socket& socket) {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);
	request_stream.write(reinterpret_cast<const char*>(&request_code), sizeof(request_code));
	request_stream.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), target_client_id.size());
	request_stream.put(message_type);

	request_stream.write(reinterpret_cast<const char*>(&message_content_size), sizeof(message_content_size));

	boost::asio::write(socket, buffer);
}

symmetricKeyRequestMessage::symmetricKeyRequestMessage(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size)
	: Message(client_id, version, request_code, payload_size, target_client_id, message_type, message_content_size) { }
void symmetricKeyRequestMessage::sendRequest(tcp::socket& socket) {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);
	request_stream.write(reinterpret_cast<const char*>(&request_code), sizeof(request_code));
	request_stream.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), target_client_id.size());
	request_stream.put(message_type);

	request_stream.write(reinterpret_cast<const char*>(&message_content_size), sizeof(message_content_size));

	// No content sent

	boost::asio::write(socket, buffer);
}


symmetricKeySendMessage::symmetricKeySendMessage(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::string encrypted_symmetric_key)
	: Message(client_id, version, request_code, payload_size, target_client_id, message_type, message_content_size), encrypted_symmetric_key(encrypted_symmetric_key) { }
void symmetricKeySendMessage::sendRequest(tcp::socket& socket) {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);
	request_stream.write(reinterpret_cast<const char*>(&request_code), sizeof(request_code));
	request_stream.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), target_client_id.size());
	request_stream.put(message_type);

	request_stream.write(reinterpret_cast<const char*>(&message_content_size), sizeof(message_content_size));
	
	request_stream.write(reinterpret_cast<const char*>(&encrypted_symmetric_key), sizeof(encrypted_symmetric_key));

	boost::asio::write(socket, buffer);
}

textMessage::textMessage(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> target_client_id, uint8_t message_type, uint32_t message_content_size, std::vector<uint8_t> message_content)
	: Message(client_id, version, request_code, payload_size, target_client_id, message_type, message_content_size), message_content(message_content) { }
void textMessage::sendRequest(tcp::socket& socket) {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);
	request_stream.write(reinterpret_cast<const char*>(&request_code), sizeof(request_code));
	request_stream.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

	request_stream.write(reinterpret_cast<const char*>(target_client_id.data()), target_client_id.size());
	request_stream.put(message_type);

	request_stream.write(reinterpret_cast<const char*>(&message_content_size), sizeof(message_content_size));

	request_stream.write(reinterpret_cast<const char*>(&message_content), sizeof(message_content));

	boost::asio::write(socket, buffer);
}



// Constructors & functions for Response classes
BaseResponse::BaseResponse(uint8_t version, uint16_t response_code, uint32_t payload_size)
	: version{ version }, response_code{ response_code }, payload_size{ payload_size } { }



RegisterResponse::RegisterResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id)
	: BaseResponse(version, response_code, payload_size), client_id(client_id) { }

std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> RegisterResponse::getClientID() {
	return client_id;
}



ClientsListResponse::ClientsListResponse(uint8_t version, uint16_t response_code, uint32_t payload_size)
	: BaseResponse(version, response_code, payload_size) { }


//////////////////////////////
void ClientHandler::addClient(const std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& client_id,
	const std::string& client_name)
{
	clients[client_id] = ClientInfo(client_name);
};

bool ClientHandler::setPublicKey(const std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& client_id,
	const std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE>& public_key)
{
	auto it = clients.find(client_id);
	if (it != clients.end()) {
		it->second.public_key = public_key;
		return true;
	}
	return false; // Client not found
};

bool ClientHandler::setSymmetricKey(const std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& client_id,
	const std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE>& symmetric_key)
{
	auto it = clients.find(client_id);
	if (it != clients.end()) {
		it->second.symmetric_key = symmetric_key;
		return true;
	}
	return false; // Client not found
};

std::optional<ClientInfo> ClientHandler::getClient(const std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE>& client_id) const
{
	auto it = clients.find(client_id);
	if (it != clients.end()) {
		return it->second;
	}
	return std::nullopt; // Client not found
};

// TODO for debugging purposes. DELETE THIS LATERRRRRRRRRRRRRRRR
void ClientHandler::printClients() const
{
	std::cout << "Clients List:\n";
	for (const auto& pair : clients) {
		std::cout << "- Client Name: " << pair.second.client_name << "\n";
		if (pair.second.public_key.has_value()) {
			std::cout << "  - Public Key: [SET]\n";
		}
		else {
			std::cout << "  - Public Key: [NOT SET]\n";
		}
		if (pair.second.symmetric_key.has_value()) {
			std::cout << "  - Symmetric Key: [SET]\n";
		}
		else {
			std::cout << "  - Symmetric Key: [NOT SET]\n";
		}
	}
};

////////////////////////////////////

PublicKeyResponse::PublicKeyResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pubkey)
	: BaseResponse(version, response_code, payload_size), client_id(client_id), pubkey(pubkey) { }

MessageSentResponse::MessageSentResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint32_t message_id)
	: BaseResponse(version, response_code, payload_size), client_id(client_id), message_id(message_id) { }

WaitingMessagesFetchResponse::WaitingMessagesFetchResponse(uint8_t version, uint16_t response_code, uint32_t payload_size)
	: BaseResponse(version, response_code, payload_size) { }

ErrorResponse::ErrorResponse(uint8_t version, uint16_t response_code, uint32_t payload_size)
	: BaseResponse(version, response_code, payload_size) { }


std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> stringToArray(const std::string& str) {
	std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> arr = {};  // Initialize with zeros
	std::memcpy(arr.data(), str.data(), std::min(str.size(), ProtocolConstants::PUBLIC_KEY_SIZE));  // Copy data
	return arr;
}


bool containsOnlyASCII(const std::string& name) {
	for (auto c : name) {
		if (static_cast<unsigned char>(c) > 127) {
			return false;
		}
	}
	return true;
}

bool isValidClientName(const std::string& client_name) {
	if (client_name.size() > 255 || (client_name.size() < 255 && client_name[client_name.size()] != '\0') || !containsOnlyASCII(client_name)) {
		return false;
	}
	return true;
}


std::unique_ptr<BaseResponse> parseResponse() {
	boost::asio::streambuf buffer; //Declare a buffer for the incoming socket bytes, for easy parsing.
	try {
		// Read the basic request (user_id, version and operation number).
		size_t basic_response_bytes = boost::asio::read(socket, buffer.prepare(ProtocolConstants::BASIC_RESPONSE_SIZE));
		if (basic_response_bytes < ProtocolConstants::BASIC_RESPONSE_SIZE) {
			throw std::runtime_error("Received data is too short to be a valid response. Not enough bytes for version, response code and payload_size fields.");
		}
		buffer.commit(ProtocolConstants::BASIC_RESPONSE_SIZE);

		std::istream input_stream(&buffer);
		uint8_t version;
		uint16_t response_code;
		uint32_t payload_size = 0;

		input_stream.read(reinterpret_cast<char*>(&version), ProtocolConstants::VERSION_SIZE);
		if (input_stream.fail()) {
			throw std::runtime_error("Failed to read version from the buffer.");
		}
		//validateField("user_id", user_id, Protocol::USER_ID_SIZE);

		input_stream.read(reinterpret_cast<char*>(&response_code), ProtocolConstants::RESPONSE_CODE_SIZE);
		if (input_stream.fail()) {
			throw std::runtime_error("Failed to read response code from the buffer.");
		}

		input_stream.read(reinterpret_cast<char*>(&payload_size), ProtocolConstants::PAYLOAD_FIELD_SIZE);
		if (input_stream.fail()) {
			throw std::runtime_error("Failed to read response code from the buffer.");
		}


		if (response_code == ProtocolConstants::Response::REGISTRATION_SUCCESS) {
			if (payload_size != ProtocolConstants::CLIENT_ID_SIZE) {
				throw std::runtime_error("Payload size has different value than what's expected in register response");
			}

			size_t id_bytes = boost::asio::read(socket, buffer.prepare(ProtocolConstants::CLIENT_ID_SIZE));
			if (id_bytes < ProtocolConstants::CLIENT_ID_SIZE) {
				throw std::runtime_error("Received data is too short to be a valid response. Not enough bytes for client id");
			}
			buffer.commit(ProtocolConstants::CLIENT_ID_SIZE);

			std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
			input_stream.read(reinterpret_cast<char*>(&client_id), ProtocolConstants::CLIENT_ID_SIZE);

			return std::make_unique<RegisterResponse>(version, response_code, payload_size, client_id);
		}
		else if (response_code == ProtocolConstants::Response::CLIENT_LIST_FETCH_SUCCESS) {
			size_t num_of_clients = payload_size / (ProtocolConstants::CLIENT_ID_SIZE + ProtocolConstants::CLIENT_NAME_SIZE);

			// Access the singleton global ClientHandler instance
			ClientHandler& handler = ClientHandler::getInstance();

			cout << "Printing Client Names (" << num_of_clients << " total): " << endl;

			for (int i = 0; i < num_of_clients; i++) {
				size_t id_bytes = boost::asio::read(socket, buffer.prepare(ProtocolConstants::CLIENT_ID_SIZE));
				if (id_bytes < ProtocolConstants::CLIENT_ID_SIZE) {
					throw std::runtime_error("Received data is too short to be a valid response. Not enough bytes for client id");
				}
				buffer.commit(ProtocolConstants::CLIENT_ID_SIZE);
				std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
				input_stream.read(reinterpret_cast<char*>(&client_id), ProtocolConstants::CLIENT_ID_SIZE);

				//client_ids.push_back(client_id);

				size_t name_bytes = boost::asio::read(socket, buffer.prepare(ProtocolConstants::CLIENT_NAME_SIZE));
				if (name_bytes < ProtocolConstants::CLIENT_NAME_SIZE) {
					throw std::runtime_error("Received data is too short to be a valid response. Not enough bytes for client name");
				}
				buffer.commit(ProtocolConstants::CLIENT_NAME_SIZE);
				std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_name_arr;
				input_stream.read(reinterpret_cast<char*>(&client_name_arr), ProtocolConstants::CLIENT_ID_SIZE);

				std::string client_name(client_name_arr.begin(), client_name_arr.end()); // Copy the array from uint8_t form to char array (to string).
				//client_names.push_back(client_name);

				handler.addClient(client_id, client_name);
				cout << i + 1 << ". " << client_name << endl;
			}

			return std::make_unique<ClientsListResponse>(version, response_code, payload_size);
		}
		else if (response_code == ProtocolConstants::Response::PUBLIC_KEY_FETCH_SUCCESS) {
			if (payload_size != ProtocolConstants::CLIENT_ID_SIZE + ProtocolConstants::PUBLIC_KEY_SIZE) {
				throw std::runtime_error("Payload size has different value than what's expected in public key response");
			}

			size_t id_bytes = boost::asio::read(socket, buffer.prepare(ProtocolConstants::CLIENT_ID_SIZE));
			if (id_bytes < ProtocolConstants::CLIENT_ID_SIZE) {
				throw std::runtime_error("Received data is too short to be a valid response. Not enough bytes for client id");
			}
			buffer.commit(ProtocolConstants::CLIENT_ID_SIZE);
			std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
			input_stream.read(reinterpret_cast<char*>(&client_id), ProtocolConstants::CLIENT_ID_SIZE);

			size_t public_key_bytes = boost::asio::read(socket, buffer.prepare(ProtocolConstants::PUBLIC_KEY_SIZE));
			if (public_key_bytes < ProtocolConstants::PUBLIC_KEY_SIZE) {
				throw std::runtime_error("Received data is too short to be a valid response. Not enough bytes for public key");
			}
			buffer.commit(ProtocolConstants::PUBLIC_KEY_SIZE);
			std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> public_key;
			input_stream.read(reinterpret_cast<char*>(&public_key), ProtocolConstants::PUBLIC_KEY_SIZE);

			return std::make_unique<PublicKeyResponse>(version, response_code, payload_size, client_id, public_key);
		}
		else if (response_code == ProtocolConstants::Response::MESSAGE_SENT_SUCCESS) {
			if (payload_size != ProtocolConstants::CLIENT_ID_SIZE + ProtocolConstants::MESSAGE_ID_SIZE) {
				throw std::runtime_error("Payload size has different value than what's expected in message sent response");
			}

			size_t id_bytes = boost::asio::read(socket, buffer.prepare(ProtocolConstants::CLIENT_ID_SIZE));
			if (id_bytes < ProtocolConstants::CLIENT_ID_SIZE) {
				throw std::runtime_error("Received data is too short to be a valid response. Not enough bytes for client id");
			}
			buffer.commit(ProtocolConstants::CLIENT_ID_SIZE);
			std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
			input_stream.read(reinterpret_cast<char*>(&client_id), ProtocolConstants::CLIENT_ID_SIZE);

			size_t message_id_bytes = boost::asio::read(socket, buffer.prepare(ProtocolConstants::MESSAGE_ID_SIZE));
			if (message_id_bytes < ProtocolConstants::MESSAGE_ID_SIZE) {
				throw std::runtime_error("Received data is too short to be a valid response. Not enough bytes for message_id");
			}
			buffer.commit(ProtocolConstants::MESSAGE_ID_SIZE);
			uint32_t message_id;
			input_stream.read(reinterpret_cast<char*>(&message_id), ProtocolConstants::MESSAGE_ID_SIZE);

			return std::make_unique<MessageSentResponse>(version, response_code, payload_size, client_id, message_id);
		}
		else if (response_code == ProtocolConstants::Response::FETCHING_INCOMING_MESSAGES_SUCCESS) {
			// Access the singleton global ClientHandler instance
			ClientHandler& handler = ClientHandler::getInstance();

			/*
			From: <username>
			Content:
			<content>
			.
			.
			.
			-----<EOM>-----
			\n
			*/
			cout << "Printing the incoming messages: " << endl;
			while (true) {
				size_t message_header_bytes = boost::asio::read(socket, buffer, boost::asio::transfer_exactly(ProtocolConstants::MESSAGE_HEADER_SIZE));
				if (message_header_bytes == 0) {
					std::cout << "No more messages. Stopping.\n";
					break;
				}
				else if (message_header_bytes != ProtocolConstants::MESSAGE_HEADER_SIZE){
					throw std::runtime_error("Received invalid message header.");
				}

				buffer.commit(ProtocolConstants::MESSAGE_HEADER_SIZE);
				
				std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id;
				uint32_t message_id;
				uint8_t message_type;
				uint32_t message_content_size;

				input_stream.read(reinterpret_cast<char*>(&client_id), ProtocolConstants::CLIENT_ID_SIZE);
				if (input_stream.fail()) {
					throw std::runtime_error("Failed to read sending client_id from the buffer.");
				}
				//validateField("user_id", user_id, Protocol::USER_ID_SIZE); // TODO delete it or make this version in this maman!!!

				input_stream.read(reinterpret_cast<char*>(&message_id), ProtocolConstants::MESSAGE_ID_SIZE);
				if (input_stream.fail()) {
					throw std::runtime_error("Failed to read message_id from the buffer.");
				}

				input_stream.read(reinterpret_cast<char*>(&message_type), ProtocolConstants::MESSAGE_TYPE_SIZE);
				if (input_stream.fail()) {
					throw std::runtime_error("Failed to read message_type from the buffer.");
				}

				input_stream.read(reinterpret_cast<char*>(&message_content_size), ProtocolConstants::MESSAGE_CONTENT_FIELD_SIZE);
				if (input_stream.fail()) {
					throw std::runtime_error("Failed to read message content size from the buffer.");
				}


				// Read the message content from the communication
				size_t message_content_bytes = boost::asio::read(socket, buffer, boost::asio::transfer_exactly(message_content_size));
				if (message_content_bytes != message_content_size) {
					throw std::runtime_error("Mismatch between message content size and message content");
				}

				buffer.commit(message_content_size);

				std::vector<uint8_t> message_content(message_content_size);
				input_stream.read(reinterpret_cast<char*>(message_content.data()), message_content_size);

				// Printing the message
				cout << "From: " << handler.getClient(client_id)->client_name << endl; 
				cout << "Content: " << endl;
				if (message_type == ProtocolConstants::Message::REQUEST_SYMMETRICAL_KEY) {
					cout << "Request For Symmetrical Key" << endl;
				}
				else if (message_type == ProtocolConstants::Message::SEND_SYMMETRICAL_KEY) {
					cout << "Symmetrical Key Received" << endl;

					// Copying the vector into an array of uint8_t for the symmetric key
					std::array<uint8_t, ProtocolConstants::SYMMETRIC_KEY_SIZE> symmetric_key = {};  // Zero-initialize
					std::copy_n(message_content.begin(), std::min(message_content.size(), ProtocolConstants::SYMMETRIC_KEY_SIZE), symmetric_key.begin());

					// Saves the symmetric key for this client.
					handler.setSymmetricKey(client_id, symmetric_key);
				}
				else if (message_type == ProtocolConstants::Message::SEND_TEXT_MESSAGE) {
					// TODO need to decrypt the message using a symmetrical key^ such as above.
					// if there's no symmetrical key or it isn't valid, we need to write "can't decrypt message".
					
					//DO IT USING A IF ELSE AND FOR THE ELSE JUST PRINT AN ERRORMESSAGE!

				}
				cout << "-----<EOM>-----" << endl;
				cout << "\n" << endl;

				// TODO add a check if the payload size is correct here? or it's unneccsarily complicated?????????????????????
				//return std::make_unique<ErrorResponse>(version, response_code, payload_size);

				
			}
			return std::make_unique<WaitingMessagesFetchResponse>(version, response_code, payload_size);
		}
		else if (response_code == ProtocolConstants::Response::GENERAL_ERROR) {
			return std::make_unique<ErrorResponse>(version, response_code, payload_size);
		}
		else {
			// TODO should i crash it here or just write an error??
		}
	}
	catch(const std::exception& e){
		std::cerr << "Error in parseResponse: " << e.what() << "\n";
		throw;
	}


}


bool CreateClientInfoFile(std::string filename, std::string username, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, std::string private_key_base64) {
	std::ofstream file(filename);
	if (!file.is_open()) {
		throw std::runtime_error("Failed to open file: " + filename);
	} // TODO maybe just return false with an error message? omgggggggg

	file << username << "\n";
	//file << client_id << "\n"; TODO how to save and write thissssssss it needs to be ascii where every 2 chars are an hex value of 8 bits.
	file << private_key_base64;
	return true;
}


void handleUserInput(int operation_code, std::shared_ptr<tcp::socket>& socket) {
	std::unique_ptr<BaseRequest> request;
	std::unique_ptr<BaseResponse> response;

	// Creating the private and public keys
	RSAPrivateWrapper rsapriv;
	std::string pubkey_str = rsapriv.getPublicKey();
	std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pubkey = stringToArray(pubkey_str);
	std::string priv_base64key = Base64Wrapper::encode(rsapriv.getPrivateKey());



	switch (operation_code) {
	case ProtocolConstants::Input_Codes::REGISTER:
	{
		string username;
		cout << "Please enter your new username (up to 254 valid ASCII characters):" << endl;
		cin >> username;
		if (!isValidClientName(username)) {
			cout << "Invalid client name." << endl;
			return;
		}


		std::array<uint8_t, 16> default_uuid;
		default_uuid.fill(0xAA);


		// Creating the request
		request = make_unique<RegisterRequest>(
			default_uuid,
			ProtocolConstants::CLIENT_VERSION,
			ProtocolConstants::Request::REGISTER_REQUEST,
			ProtocolConstants::REGISTER_PAYLOAD_SIZE,
			username,
			pubkey
		);

		// Send the registration request
		request->sendRequest(*socket); // TODO is it correct?

		// Receive a response
		response = parseResponse();
		
		// TODO add a check if the response is correct AND isn't an error.

		const string filename = "me.info";
		if (doesFileExist(filename)) {
			cerr << "Warning: me.info file already exists, cancelling sign up operation." << endl;
			return;
		}

		// Getting the client_id from the RegisterResponse class
		if (auto* regResponse = dynamic_cast<RegisterResponse*>(response.get())) {
			auto clientID = regResponse->getClientID();
			CreateClientInfoFile(filename, username, clientID, priv_base64key);
		}
		else {
			cerr << "Warning: me.info file already exists, cancelling sign up operation." << endl;
			return; // TODO write a different error here.
		}

		cout << "New client details are saved in me.info file." << endl;
		break;
	}
	case ProtocolConstants::Input_Codes::CLIENTS_LIST:
	{

		break;
	}
	case ProtocolConstants::Input_Codes::FETCH_OTHER_CLIENT_PUBLIC_KEY:
	{

		break;
	}
	case ProtocolConstants::Input_Codes::FETCH_WAITING_MESSAGES:
	{

		break;
	}
	case ProtocolConstants::Input_Codes::SEND_TEXT_MESSAGE_CODE:
	{

		break;
	}
	case ProtocolConstants::Input_Codes::SEND_REQUEST_SYMMETRIC_KEY:
	{

		break;
	}
	case ProtocolConstants::Input_Codes::SEND_SYMMETRIC_KEY:
	{

		break;
	}
	default:
		cout << "Please enter one of the valid options.\n";
		break;
	}
	return;
}


/*
	Connect to the server and return the socket.
*/
std::shared_ptr<tcp::socket> connectToServer(const string& ip, const string& port, boost::asio::io_context& io_context) {
	auto socket = std::make_shared<tcp::socket>(io_context);
	tcp::resolver resolver(io_context);
	boost::asio::connect(*socket, resolver.resolve(ip, port));

	return socket;
}

bool doesFileExist(const std::string& filename) {
	if (filesystem::exists(filename)) {
		return true;
	}
	else {
		//throw std::runtime_error("File " + filename + " doesn't exist. Aborting connection.");
		return false;
	}
}


bool isPortValid(const string& port) {
	if (port.length() <= 5 || port.find_first_not_of("0123456789") != std::string::npos) {
		int num_port = std::stoi(port);
		if (num_port < 0 || num_port > 65353) {
			return false;
		}
		else {
			return true;
		}
	}
	else {
		return false;
	}
}

bool isIPvalid(const string& ip) {
	try {
		boost::asio::ip::make_address(ip); // This will throw if the IP is invalid
		return true;
	}
	catch (...) {
		return false;
	}
}

void clearFileAndResetPointer(std::ifstream& file) {
	file.clear();
	file.seekg(0, std::ios::beg);
}

std::string readIPfromFile(std::string& line) {
	size_t separator = line.find(':');
	return line.substr(0, separator);
}

std::string readPortfromFile(std::string& line) {
	size_t separator = line.find(':');
	return line.substr(separator + 1);
}

std::string validate_server_file(std::ifstream& file) {
	std::string line;

	std::getline(file, line);
	if (!file.eof()) {
		throw std::runtime_error("Too many lines in server.info file");
	}

	clearFileAndResetPointer(file);

	// Split by ':'
	size_t separator = line.find(':');
	if (separator == std::string::npos) {
		throw std::runtime_error("no ':' found in server.info file");
	}

	std::string ip = line.substr(0, separator);
	std::string port = line.substr(separator + 1);

	if (!isIPvalid(ip) || !isPortValid(port)) {
		throw std::runtime_error("Invalid IP or Port in server.info file");
	}

	return line;
}


int main() {
	boost::asio::io_context io_context;
	try {
		std::string filename = "server.info";
		if (!doesFileExist(filename)) {
			throw std::runtime_error("File " + filename + " doesn't exist.");
		}
		std::ifstream file(filename);
		if (!file.is_open()) {
			throw std::runtime_error("Failed to open file: " + filename);
		}
		std::string info_line = validate_server_file(file);
		std::string ip = readIPfromFile(info_line);
		std::string port = readPortfromFile(info_line);
		file.close();

		//testinggggggggggg
		cout << ip << endl;
		cout << port << endl;

		////////////////////

		while (true) {
			int responseCode;
			cout << "MessageU client at your service.\n" << endl;
			cout << "110) Register\n120) Request for clients list\n130) Request for public key\n140) Request for waiting messages" << endl;
			cout << "150) Send a text message\n151) Send a request for symmetric key\n152) Send your symmetric key\n0) Exit client\n?" << endl;
			if (cin >> responseCode) {
				if (responseCode == ProtocolConstants::Input_Codes::EXIT_CLIENT) {
					cout << "\nThanks for using MessageU!" << endl;
					break;
				}
				else {
					auto socket = connectToServer(ip, port, io_context);
					handleUserInput(responseCode, socket);
				}
			}
			else { //Non numberical input, clear the input stream!
				cout << "Non-numberical input deteced. Please enter one of the valid options.\n";
				cin.clear();
				cin.ignore(numeric_limits<streamsize>::max(), '\n');
			}
			cout << "-----------------------------------------------------" << endl;
		}
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << "\n";
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
