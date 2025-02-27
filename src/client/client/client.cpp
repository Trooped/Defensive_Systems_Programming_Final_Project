/*
	ADD DOCUMENTATION

*/


#include "client.hpp"

using namespace std;
using boost::asio::ip::tcp;

//Constructors for Request & Message classes and inheriting classes.
BaseRequest::BaseRequest(std::array<uint8_t, 16> client_id, uint8_t version, uint16_t request_code, uint32_t payload_size)
	: client_id{ client_id }, version{ version }, request_code{ request_code }, payload_size{ payload_size } { }

void BaseRequest::sendRequest(tcp::socket& socket) {
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

std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> RegisterRequest::stringToArray(const std::string& str) {
	std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> arr = {};  // Initialize with zeros
	std::memcpy(arr.data(), str.data(), std::min(str.size(), ProtocolConstants::PUBLIC_KEY_SIZE));  // Copy data
	return arr;
}
void RegisterRequest::sendRequest(tcp::socket& socket) {
	boost::asio::streambuf buffer;
	std::ostream request_stream(&buffer);
	request_stream.write(reinterpret_cast<const char*>(client_id.data()), client_id.size());

	request_stream.put(version);
	request_stream.write(reinterpret_cast<const char*>(&request_code), sizeof(request_code));
	request_stream.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));

	while (client_name.length() < 255) {
		client_name.append('\0');
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

// handle the client list response!!!!!!!!!!!!!!

PublicKeyResponse::PublicKeyResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pubkey)
	: BaseResponse(version, response_code, payload_size), client_id(client_id), pubkey(pubkey) { }

MessageSentResponse::MessageSentResponse(uint8_t version, uint16_t response_code, uint32_t payload_size, std::array<uint8_t, ProtocolConstants::CLIENT_ID_SIZE> client_id, uint32_t message_id)
	: BaseResponse(version, response_code, payload_size), client_id(client_id), message_id(message_id) { }

// handle the waiting messages fetch response!!!!!!!!!!!!!!!!!!!!!!

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





void handleRegisterRequest(std::unique_ptr<BaseRequest> request, std::unique_ptr<BaseResponse> response) {
	string username;
	cout << "Please enter your new username (up to 254 valid ASCII characters):" << endl;
	cin >> username;
	if (!isValidClientName(username)) {
		cout << "Invalid client name." << endl;
		return;
	}

	// Creating the private and public keys
	RSAPrivateWrapper rsapriv;
	std::string pubkey_str = rsapriv.getPublicKey();
	std::array<uint8_t, ProtocolConstants::PUBLIC_KEY_SIZE> pubkey = stringToArray(pubkey_str);
	std::string priv_base64key = Base64Wrapper::encode(rsapriv.getPrivateKey());

	// Creating the request
	request = make_unique<RegisterRequest>(
		ProtocolConstants::DEFAULT_CLIENT_ID,
		ProtocolConstants::CLIENT_VERSION,
		ProtocolConstants::Request::REGISTER_REQUEST,
		ProtocolConstants::REGISTER_PAYLOAD_SIZE,
		username,
		pubkey
	);

	// Send the request
	
	//socket!!!!!!!!!!!!!!! request->sendRequest();
	

	// Receive a response
	//************ MAYBE CREATE A GENERIC RESPONSE POINTER IN THE HANDLEUSERINPUT AND THEN REUSE IT THROUGH ALL OF THE FUNCTIONS


	// Enter the clientname, the ID and the private key in base 64 into the me.info file


}


void handleUserInput(int operation_code) {
	std::unique_ptr<BaseRequest> request;

	switch (operation_code) {
	case ProtocolConstants::Input_Codes::REGISTER:
	{

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

void inputLoop() {
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
				handleUserInput(responseCode);
			}
		}
		else { //Non numberical input, clear the input stream!
			cout << "Non-numberical input deteced. Please enter one of the valid options.\n";
			cin.clear();
			cin.ignore(numeric_limits<streamsize>::max(), '\n');
		}
		cout << "-----------------------------------------------------" << endl;
	}
	return;
}


void main() {
	inputLoop();
	return;
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
