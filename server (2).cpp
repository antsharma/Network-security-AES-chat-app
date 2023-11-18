#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <bits/stdc++.h>

#define PORT 8000
#define IP "127.0.0.1"
#define MAX_CLIENTS 5

int server_sock, client_socket[MAX_CLIENTS], new_socket;
int opt = 1, max_sd, sd, valread;
struct sockaddr_in address;
socklen_t addrlen = sizeof(address);
fd_set fds;
struct timeval timeout;
char buffer[1024] = {0};
char keys[MAX_CLIENTS][1024];
std::unordered_map<int, std::string> clients;

int init_Server();
void IncomingConnection();
void forwardData(int);
void exchangeKey(int sfd, int idx);

int main() {
    
    if (init_Server()) exit(EXIT_FAILURE);

    for (int i=0; i<MAX_CLIENTS; i++) {
        client_socket[i] = -1;
    }

    while (true) {
        FD_ZERO(&fds);

        FD_SET(server_sock, &fds);
        max_sd = server_sock;
             
        //add child sockets to set 
        for (int i = 0; i < MAX_CLIENTS; i++)  
        {  
            //socket descriptor 
            sd = client_socket[i];  
                 
            //if valid socket descriptor then add to read list 
            if(sd >= 0) {
                FD_SET(sd, &fds);
            }
                 
            //highest file descriptor number, need it for the select function 
            if(sd > max_sd)
                max_sd = sd;
        }

        // wait for an activity on one of the sockets, timeout is NULL , 
        // so wait indefinitely 
        int activity = select(max_sd+1, &fds, NULL, NULL, NULL);

        if ((activity < 0) && (errno!=EINTR))
        {  
            printf("select error");
        }

        //If something happened on the master socket, then its an incoming connection 
        if (FD_ISSET(server_sock, &fds))  
        {  
            IncomingConnection();
        }

        // Else its an IO operation
        for (int i = 0; i < MAX_CLIENTS; i++)  
        {  
            sd = client_socket[i];
            if (sd >= 0 && FD_ISSET(sd, &fds))
            {
                printf("IO detected on socket %d: ", sd);
                bzero(buffer, 1024);
                int ret_val = recv(sd, buffer, sizeof(buffer), 0);
                if (ret_val == 0) {
                    printf("Closing connection for fd:%d\n", sd);
                    close(sd);
                    client_socket[i] = -1;
                }
                else if (ret_val > 0) { 
                    printf("Received data (len %d bytes, fd: %d)\n", ret_val, sd);
                    forwardData(sd);
                }
                else if (ret_val == -1) {
                    printf("recv() failed for fd: %d [%s]\n", sd, strerror(errno));
                    break;
                }
            }
        }
    }

    shutdown(server_sock,SHUT_RDWR);

    return 0;
}

int init_Server() {
    server_sock = socket(AF_INET,SOCK_STREAM,0);
    if (server_sock < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);

    if (inet_pton(AF_INET, IP, &address.sin_addr) <= 0) {
        printf("\nInvalid IP address\n");
        address.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(server_sock, (struct sockaddr*)&address, addrlen) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock,4) < 0) {
        perror("listen error");
        exit(EXIT_FAILURE);
    }
    
    printf("[] Server running at ip : %s, port : %d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
    printf("[] Open to connections\n");
    return 0;
}

void IncomingConnection() {
    if ((new_socket = accept(server_sock, (struct sockaddr *)&address, &addrlen))<0)  
    {  
        perror("accept");
        exit(EXIT_FAILURE);  
    }  
    
    //inform user of socket number - used in send and receive commands 
    printf("New connection , socket fd is %d , ip is : %s , port : %d \n", new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
    
    //send new connection greeting message
    // char welcome[10] = "Hello";
    // if (send(new_socket, welcome, strlen(welcome), 0) != strlen(welcome) )  
    // {
    //     perror("send");
    // }
    // puts("Welcome message sent successfully");

    // add new socket to array of sockets 
    int idx;
    for (int i = 0; i < MAX_CLIENTS; i++)  
    {  
        //if position is empty 
        if(client_socket[i] == -1)
        {  
            client_socket[i] = new_socket;  
            idx = i;
            printf("Adding to list of sockets as %d\n" , i);
            break;  
        }
    }
    
    recv(client_socket[idx], keys[idx], sizeof(keys[idx]), 0);
    exchangeKey(new_socket, idx);
    
}

void exchangeKey(int sfd, int idx) {
	for (int i=0; i<=MAX_CLIENTS; i++) {
        if (client_socket[i] >= 0 && client_socket[i] != sfd) {
            send(client_socket[i], keys[idx], strlen(keys[idx]), 0);
            send(client_socket[idx], keys[i], strlen(keys[i]), 0);
        }
    }
}

void forwardData(int sfd) {
    for (int i=0; i<MAX_CLIENTS; i++) {
        if (client_socket[i] >= 0 && client_socket[i] != sfd) {
            send(client_socket[i], buffer, strlen(buffer), 0);
        }
    }
}
