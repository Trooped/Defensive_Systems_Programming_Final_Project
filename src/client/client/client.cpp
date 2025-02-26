/*
	ADD DOCUMENTATION

*/


#include "client.h"

using namespace std;
using boost::asio::ip::tcp;

//Constructors for Request & Message classes and inheriting classes.

Request::Request(string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size) 
	: client_id{ client_id }, version{ version }, request_code{ request_code }, payload_size{ payload_size } { }

registerRequest::registerRequest(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string client_name, std::string public_key)
	: Request(client_id, version, request_code, payload_size), client_name(client_name), public_key(public_key) { }

basicRequest::basicRequest(string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size)
	: Request(client_id, version, request_code, payload_size) { }

publicKeyRequest::publicKeyRequest(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id)
	: Request(client_id, version, request_code, payload_size), target_client_id(target_client_id) { }

Message::Message(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size)
	: Request(client_id, version, request_code, payload_size), target_client_id(target_client_id), message_type(message_type), message_content_size(message_content_size) { }

symmetricKeyRequestMessage::symmetricKeyRequestMessage(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size)
	: Message(client_id, version, request_code, payload_size, target_client_id, message_type, message_content_size) { }

symmetricKeySendMessage::symmetricKeySendMessage(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size, std::string encrypted_symmetric_key)
	: Message(client_id, version, request_code, payload_size, target_client_id, message_type, message_content_size), encrypted_symmetric_key(encrypted_symmetric_key) { }

textMessage::textMessage(std::string client_id, uint8_t version, uint16_t request_code, uint32_t payload_size, std::string target_client_id, uint8_t message_type, uint32_t message_content_size, std::vector<uint8_t> message_content)
	: Message(client_id, version, request_code, payload_size, target_client_id, message_type, message_content_size), message_content(message_content) { }


void inputLoop() {
	while (true) {
		int response;
		cout << "MessageU client at your service.\n" << endl;
		cout << "110) Register\n120) Request for clients list\n 130) Request for public key\n 140) Request for waiting messages" << endl;
		cout << "150) Send a text message\n151) Send a request for symmetric key\n 152) Send your symmetric key\n0) Exit client\n?" << endl;
		cin >> response;

		switch (response) {
		case ProtocolConstants::Input_Codes::REGISTER:
		{
			string username;
			cout << "Please enter your new username (up to 254 valid ASCII characters):" << endl;
			cin >> username;
			//ADD A CALL TO A FUNCTION THAT CHECKS LENGTH AND ONLY ASCII CHARACTERS FOR THE INPUT STRING.
			// MAYBE create a class for basic user info? username, uuid and public key?

			//now call the function with the parameters :)

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
		case ProtocolConstants::Input_Codes::SEND_TEXT_MESSAGE:
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
		case ProtocolConstants::Input_Codes::EXIT_CLIENT:
		{

			break;
		}
		default:
			cout << "Wrong input, please enter one of the valid options.\n";
		}





		if (response == 0) {
			cout << "\nThanks for using MessageU!" << endl;
			break;
		}

	}
}





void main() {
	inputLoop();
	return;
}