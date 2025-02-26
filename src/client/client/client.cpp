#include <iostream>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

void main() {
	int port = 1234;
	const int max_Length = 1042;
	boost::asio::io_context io_context;
	tcp::acceptor a(io_context, tcp::endpoint(tcp::v4(), port));
	tcp::socket sock = a.accept(); // this waits for client to open session

	char data[max_Lenth];
	// next command will wait for client to send data
	size_t length = boost::asio::read(sock, boost::asio::buffer(data, max_Length));
}