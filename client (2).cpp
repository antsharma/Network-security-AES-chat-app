#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <bits/stdc++.h>
#include "cryptopp880/aes.h"
#include "cryptopp880/filters.h"
#include "cryptopp880/modes.h"
#include "cryptopp880/dh.h"
#include "cryptopp880/dh2.h"
#include "cryptopp880/osrng.h"
#include "cryptopp880/secblock.h"
#include "cryptopp880/hex.h"
#include <fcntl.h>
using namespace CryptoPP;
#define PORT 8000
#define SERVER_IP "127.0.0.1"

int sockfd,client_fd;
struct sockaddr_in server_addr;
socklen_t addrlen = sizeof(server_addr);
fd_set readfds, writefds;
struct timeval timeout;
std::stringstream ss;
std::string aesKey;						 // 128-bit key
std::string iv = "1234567890abcdef";     // 128-bit IV
char buffer[1024] = {0};
char message[1024];
char username[128], otheruser[128];
long long int P, G, a, A, key;
int ConnectServer();

std::string EncryptAES(const char* input, const std::string& key, const std::string& iv);
std::string DecryptAES(const std::string& cipherText, const std::string& key, const std::string& iv);

long long int power(long long int a, long long int b, long long int P) {
    if (b == 0)
        return 1;
    long long int res = power(a, b/2, P);
    res = (res * res) % P;
    if (b % 2 == 1)
    	res = (res * a) % P;
    return res;
}

int main() {
	P = 23; // Chosen prime number
	G = 9; // primitive root of P0
	a = rand() % (P-1) + 1; // private key
	A = power(G, a, P); // public key
    
    // Connect to Server
    if(ConnectServer()) exit(EXIT_FAILURE);

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);

        timeout.tv_sec = 0; // Set a timeout for select() (5 seconds)
        timeout.tv_usec = 0;

        int activity = select(sockfd+1, &readfds, NULL, NULL, &timeout);

        if ((activity < 0) && (errno!=EINTR))
        {  
            printf("select error");
        }

        if (FD_ISSET(sockfd, &readfds)) {
            bzero(buffer, 1024);
            int ret_val = recv(sockfd, buffer, sizeof(buffer), 0);
            if (ret_val == 0) {
                printf("Closing connection for fd:%d\n", sockfd);
                close(sockfd);
                sockfd = -1; /* Connection is now closed */
            } 
            else if (ret_val > 0) {
                printf("Encrypted Text received: %s\n", buffer);
             	std::string receivedMessage(buffer);
                std::string plaintext = DecryptAES(receivedMessage, aesKey, iv);
		        std::cout << ">> " << plaintext << std::endl;
            }
            else if (ret_val == -1) {
                printf("recv() failed for fd: %d [%s]\n", sockfd, strerror(errno));
                break;
            }
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            // Input is available, read it
            if (fgets(message, sizeof(message), stdin) != NULL) {
                // Process and display the received input
                message[strlen(message) - 1] = '\0';
                std::string encryptedText = EncryptAES(message, aesKey, iv);
                const char* bufferMsg = encryptedText.c_str();
                send(sockfd, bufferMsg, strlen(bufferMsg), 0);
            } else {
                perror("fgets");
                break;
            }
        }
    }

    close(client_fd);
    close(sockfd);

    return 0;
}

int ConnectServer() {
    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if (sockfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    client_fd = connect(sockfd, (struct sockaddr*)&server_addr, addrlen);
    if (client_fd < 0) {
        perror("connect failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to Server\n");
    
    memcpy(message, &A, sizeof(long long int));
    send(sockfd, message, sizeof(message), 0);
    
    recv(sockfd, buffer, sizeof(buffer), 0);
    memcpy(&key, buffer, sizeof(long long int));    
    key = power(key, a, P);
    ss << std::hex << std::setw(16) << std::setfill('0') << key;
    aesKey = ss.str();
    // std::cout << key << " " << aesKey << std::endl;
    return 0;
}

std::string EncryptAES(const char* input, const std::string& key, const std::string& iv) {
    std::string encryptedText;

    try {
        // Create AES encryption object
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());

        // Perform encryption
        StringSource(input, true, new StreamTransformationFilter(encryption, new StringSink(encryptedText), BlockPaddingSchemeDef::PKCS_PADDING));
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "AES encryption error: " << e.what() << std::endl;
    }

    return encryptedText;
}

// Decrypts the cipher text using AES decryption and returns the original text
std::string DecryptAES(const std::string& cipherText, const std::string& key, const std::string& iv) {
    std::string decryptedText;

    try {
        // Create AES decryption object
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());

        // Perform decryption
        StringSource(cipherText, true, new StreamTransformationFilter(decryption, new StringSink(decryptedText), BlockPaddingSchemeDef::NO_PADDING));
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "AES decryption error: " << e.what() << std::endl;
    }
    // Remove PKCS#7 padding manually
    size_t paddingSize = decryptedText.back();
    decryptedText.resize(decryptedText.size() - paddingSize);

    return decryptedText;
}
