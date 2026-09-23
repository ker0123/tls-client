/// 尝试和我字节的服务器做 tls 握手

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "tlsclient.h"

using namespace std;

int main() {
    auto now = []() -> std::string {
        auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm tm{};
        localtime_s(&tm, &t);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%H:%M:%S");
        return oss.str();
    };

    // 把 CA, 证书和私钥从文件读为字符串

    fstream ca_file("crt&key/Tester.pem", ios::in);
    fstream cert_file("crt&key/Tester.pem", ios::in);
    fstream key_file("crt&key/Tester.key", ios::in);
    if (!ca_file.is_open() || !cert_file.is_open() || !key_file.is_open()) {
        cerr << "Failed to open ca, cert or key" << endl;
        return 1;
    }
    string ca((istreambuf_iterator<char>(ca_file)), istreambuf_iterator<char>());
    string cert((istreambuf_iterator<char>(cert_file)), istreambuf_iterator<char>());
    string key((istreambuf_iterator<char>(key_file)), istreambuf_iterator<char>());

    // 创建一个 tcp socket, 连接到我的 https 服务器
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "WSAStartup failed" << endl;
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        cerr << "socket() failed: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(30504);
    inet_pton(AF_INET, "192.168.69.21", &addr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        cerr << "connect() failed: " << WSAGetLastError() << endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    cout << "[" << now() << "] TCP connected to 192.168.69.21:30504" << endl;

    // 创建一个 TlsClient 对象, 并进行握手和发送数据
    TlsClient client(static_cast<int>(sock), {false, true, ca, cert, key, ""s});
    auto result = client.init();
    cout << "[" << now() << "] init() -> " << result.get_code() << ": " << result.get_message() << endl;
    result = client.hand_shake();
    cout << "[" << now() << "] hand_shake() -> " << result.get_code() << ": " << result.get_message() << endl;
    string cmd = "\x10\x02\x00\x07\x00\x02\x01\x00\x00\x00\x00\x00\x00"s;
    vector<uint8_t> buffer(cmd.begin(), cmd.end());
    result = client.send(buffer.data(), buffer.size());
    cout << "[" << now() << "] send() -> " << result.get_code() << ": " << result.get_message() << endl;
    vector<uint8_t> recv_buffer(1024);
    result = client.recv(recv_buffer.data(), recv_buffer.size());
    cout << "[" << now() << "] recv() -> " << result.get_code() << ": " << result.get_message() << endl;
    result = client.shutdown();
    cout << "[" << now() << "] shutdown() -> " << result.get_code() << ": " << result.get_message() << endl;

    // 关闭 socket 和清理 winsock
    closesocket(sock);
    WSACleanup();
    return 0;
}
