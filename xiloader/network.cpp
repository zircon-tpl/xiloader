/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/

===========================================================================
*/

#include "network.h"

#include <thread>

namespace xiloader
{
    /**
     * @brief Creates a connection on the given port.
     *
     * @param sock          The datasocket object to store information within.
     * @param server        Server address to connect.
     * @param port          The port to create the connection on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateConnection(datasocket* sock, const std::string& server, const char* port)
    {
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        /* Attempt to get the server information. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(server.c_str(), port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain remote server information.");
            return 0;
        }

        char localAddress[INET_ADDRSTRLEN];

        /* Determine which address is valid to connect.. */
        for (auto ptr = addr; ptr != NULL; ptr->ai_next)
        {
            /* Attempt to create the socket.. */
            sock->s = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (sock->s == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::error, "Failed to create socket.");

                freeaddrinfo(addr);
                return 0;
            }

            /* Attempt to connect to the server.. */
            if (connect(sock->s, ptr->ai_addr, ptr->ai_addrlen) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to connect to server!");

                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return 0;
            }

            // Find connected client address via peer
            struct sockaddr peer;
            int peer_len = sizeof(peer);
            if (getpeername(sock->s, &peer, &peer_len))
            {
                xiloader::console::output(xiloader::color::error, "Failed to obtain remote client information.");
                return 0;
            }

            inet_ntop(AF_INET, &(((struct sockaddr_in*)&peer)->sin_addr), localAddress, INET_ADDRSTRLEN);
            xiloader::console::output(xiloader::color::info, "Connected to server!");

            break;
        }

        inet_pton(AF_INET, localAddress, &sock->LocalAddress);
        inet_pton(AF_INET, server.c_str(), &sock->ServerAddress);

        return 1;
    }

    /**
     * @brief Creates a listening server on the given port and protocol.
     *
     * @param sock      The socket object to bind to.
     * @param protocol  The protocol to use on the new listening socket.
     * @param port      The port to bind to listen on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateListenServer(SOCKET* sock, int protocol, const char* port)
    {
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
        hints.ai_protocol = protocol;
        hints.ai_flags = AI_PASSIVE;

        /* Attempt to resolve the local address.. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(NULL, port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain local address information.");
            return false;
        }

        /* Create the listening socket.. */
        *sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (*sock == INVALID_SOCKET)
        {
            xiloader::console::output(xiloader::color::error, "Failed to create listening socket.");

            freeaddrinfo(addr);
            return false;
        }

        /* Bind to the local address.. */
        if (bind(*sock, addr->ai_addr, (int)addr->ai_addrlen) == SOCKET_ERROR)
        {
            xiloader::console::output(xiloader::color::error, "Failed to bind to listening socket.");

            freeaddrinfo(addr);
            closesocket(*sock);
            *sock = INVALID_SOCKET;
            return false;
        }

        freeaddrinfo(addr);

        /* Attempt to listen for clients if we are using TCP.. */
        if (protocol == IPPROTO_TCP)
        {
            if (listen(*sock, SOMAXCONN) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to listen for connections.");

                closesocket(*sock);
                *sock = INVALID_SOCKET;
                return false;
            }
        }

        return true;
    }

    /**
     * @brief Resolves the given hostname to its long ip format.
     *
     * @param host      The host name to resolve.
     * @param lpOutput  Pointer to a ULONG to store the result.
     *
     * @return True on success, false otherwise.
     */
    bool network::ResolveHostname(const char* host, PULONG lpOutput)
    {
        struct addrinfo hints, *info = 0;
        memset(&hints, 0, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(host, "1000", &hints, &info))
            return false;

        *lpOutput = ((struct sockaddr_in*)info->ai_addr)->sin_addr.S_un.S_addr;

        freeaddrinfo(info);
        return true;
    }

    /**
     * @brief Verifies the players login information; also handles creating new accounts.
     *
     * @param sock          The datasocket object with the connection socket.
     * @param server        Server address to connect.
     * @param username      Account username.
     * @param password      Account password.
     *
     * @return True on success, false otherwise.
     */
    bool network::VerifyAccount(datasocket* sock, const std::string& server, std::string& username, std::string& password)
    {
        static bool bCanAutoLogin = true;

        char recvBuffer[1024] = { 0 };
        char sendBuffer[1024] = { 0 };

        /* Create connection if required.. */
        if (sock->s == NULL || sock->s == INVALID_SOCKET)
        {
            if (!xiloader::network::CreateConnection(sock, server, "54231"))
                return false;
        }

        /* Determine if we should auto-login.. */
        bool bUseAutoLogin = !username.empty() && !password.empty() && bCanAutoLogin;
        if (bUseAutoLogin)
            xiloader::console::output(xiloader::color::lightgreen, "Autologin activated!");

        if (!bUseAutoLogin)
        {
            bCanAutoLogin = false;
            xiloader::console::output("==========================================================");
            xiloader::console::output("What would you like to do?");
            xiloader::console::output("   1.) Login");
            xiloader::console::output("   2.) Create New Account");
            xiloader::console::output("   3.) Change Account Password");
            xiloader::console::output("==========================================================");
            printf("\nEnter a selection: ");

            std::string input;
            std::cin >> input;
            std::cout << std::endl;

            /* User wants to log into an existing account or modify an existing account's password. */
            if (input == "1" || input == "3")
            {
                if (input == "3")
                    xiloader::console::output("Before resetting your password, first verify your account details.");
                xiloader::console::output("Please enter your login information.");
                std::cout << "\nUsername: ";
                std::cin >> username;
                std::cout << "Password: ";
                password.clear();

                /* Read in each char and instead of displaying it. display a "*" */
                char ch;
                while ((ch = static_cast<char>(_getch())) != '\r')
                {
                    if (ch == '\0')
                        continue;
                    else if (ch == '\b')
                    {
                        if (password.size())
                        {
                            password.pop_back();
                            std::cout << "\b \b";
                        }
                    }
                    else
                    {
                        password.push_back(ch);
                        std::cout << '*';
                    }
                }
                std::cout << std::endl;

                char event_code = (input == "1") ? 0x10 : 0x30;
                sendBuffer[0x20] = event_code;
            }
            /* User wants to create a new account.. */
            else if (input == "2")
            {
            create_account:
                xiloader::console::output("Please enter your desired login information.");
                std::cout << "\nUsername (3-15 characters): ";
                std::cin >> username;
                std::cout << "Password (6-15 characters): ";
                password.clear();
                std::cin >> password;
                std::cout << "Repeat Password           : ";
                std::cin >> input;
                std::cout << std::endl;

                if (input != password)
                {
                    xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
                    goto create_account;
                }

                sendBuffer[0x20] = 0x20;
            }

            std::cout << std::endl;
        }
        else
        {
            /* User has auto-login enabled.. */
            sendBuffer[0x20] = 0x10;
            bCanAutoLogin = false;
        }

        /* Copy username and password into buffer.. */
        memcpy(sendBuffer + 0x00, username.c_str(), 16);
        memcpy(sendBuffer + 0x10, password.c_str(), 16);

        /* Send info to server and obtain response.. */
        send(sock->s, sendBuffer, 33, 0);
        recv(sock->s, recvBuffer, 16, 0);

        /* Handle the obtained result.. */
        switch (static_cast<AccountResult>(recvBuffer[0]))
        {
        case AccountResult::Login_Success: // 0x001
            xiloader::console::output(xiloader::color::success, "Successfully logged in as %s!", username.c_str());
            sock->AccountId = *(UINT32*)(recvBuffer + 0x01);
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return true;

        case AccountResult::Login_Error: // 0x002
            xiloader::console::output(xiloader::color::error, "Failed to login. Invalid username or password.");
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return false;

        case AccountResult::Create_Success: // 0x003
            xiloader::console::output(xiloader::color::success, "Account successfully created!");
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            bCanAutoLogin = true;
            return false;

        case AccountResult::Create_Taken: // 0x004
            xiloader::console::output(xiloader::color::error, "Failed to create account. Username already taken.");
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return false;

        case AccountResult::Create_Disabled: // 0x008
            xiloader::console::output(xiloader::color::error, "Failed to create account. This server does not allow account creation through the loader.");
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return false;

        case AccountResult::Create_Error: // 0x009
            xiloader::console::output(xiloader::color::error, "Failed to created account, a server-side error occurred.");
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return false;

        case AccountResult::PassChange_Request: // Request for updated password to change to.
            xiloader::console::output(xiloader::color::success, "Log in verified for user %s.", username.c_str());
            std::string confirmed_password = "";
            do
            {
                std::cout << "Enter new password (6-15 characters): ";
                password.clear();
                std::cin >> password;
                std::cout << "Repeat Password           : ";
                std::cin >> confirmed_password;
                std::cout << std::endl;

                if (password != confirmed_password)
                {
                    xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
                }
            } while (password != confirmed_password);

            /* Clear the buffers */
            memset(sendBuffer, 0, 33);
            memset(recvBuffer, 0, 16);

            /* Copy the new password into the buffer. */
            memcpy(sendBuffer, password.c_str(), 16);

            /* Send info to server and obtain response.. */
            send(sock->s, sendBuffer, 16, 0);
            recv(sock->s, recvBuffer, 16, 0);

            /* Handle the final result. */
            switch (static_cast<AccountResult>(recvBuffer[0]))
            {
            case AccountResult::PassChange_Success: // Success (Changed Password)
                xiloader::console::output(xiloader::color::success, "Password updated successfully!");
                std::cout << std::endl;
                password.clear();
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return false;

            case AccountResult::PassChange_Error: // Error (Changed Password)
                xiloader::console::output(xiloader::color::error, "Failed to change password.");
                std::cout << std::endl;
                password.clear();
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return false;
            }
        }

        /* We should not get here.. */
        closesocket(sock->s);
        sock->s = INVALID_SOCKET;
        return false;
    }

    /**
     * @brief Data communication between the local client and the game server.
     *
     * @param socket        Pointer to communication socket.
     * @param server        Server address to connect.
     * @param characterList Pointer to character list in memory.
     * @param sharedState   Shared thread state (bool, mutex, condition_variable).
     *
     * @return void.
     */
    void network::FFXiDataComm(xiloader::datasocket* socket, const std::string& server, char*& characterList, xiloader::SharedState& sharedState)
    {
        /* Attempt to create connection to the server.. */
        if (!xiloader::network::CreateConnection(socket, server, "54230"))
        {
            xiloader::console::output("Failed connection to Server");
            xiloader::NotifyShutdown(sharedState);
            return;
        }

        int sendSize = 0;
        char recvBuffer[4096] = { 0 };
        char sendBuffer[4096] = { 0 };

        while (sharedState.isRunning)
        {
            /* Attempt to receive the incoming data.. */
            struct sockaddr_in client;
            unsigned int socksize = sizeof(client);
            if (recvfrom(socket->s, recvBuffer, sizeof(recvBuffer), 0, (struct sockaddr*)&client, (int*)&socksize) == SOCKET_ERROR)
            {
                xiloader::NotifyShutdown(sharedState);
                return;
            }

            switch (recvBuffer[0])
            {
            case 0x0001:
                sendBuffer[0] = 0xA1u;
                memcpy(sendBuffer + 0x01, &socket->AccountId, 4);
                memcpy(sendBuffer + 0x05, &socket->ServerAddress, 4);
                xiloader::console::output(xiloader::color::warning, "Sending account id..");
                sendSize = 9;
                break;

            case 0x0002:
            case 0x0015:
                memcpy(sendBuffer, (char*)"\xA2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58\xE0\x5D\xAD\x00\x00\x00\x00", 25);
                xiloader::console::output(xiloader::color::warning, "Sending key..");
                sendSize = 25;
                break;

            case 0x0003:
                xiloader::console::output(xiloader::color::warning, "Receiving character list..");
                for (auto x = 0; x <= recvBuffer[1]; x++)
                {
                    characterList[0x00 + (x * 0x68)] = 1;
                    characterList[0x02 + (x * 0x68)] = 1;
                    characterList[0x10 + (x * 0x68)] = (char)x;
                    characterList[0x11 + (x * 0x68)] = 0x80u;
                    characterList[0x18 + (x * 0x68)] = 0x20;
                    characterList[0x28 + (x * 0x68)] = 0x20;

                    memcpy(characterList + 0x04 + (x * 0x68), recvBuffer + 0x14 * (x + 1), 4); // Character Id
                    memcpy(characterList + 0x08 + (x * 0x68), recvBuffer + 0x10 * (x + 1), 4); // Content Id
                }
                sendSize = 0;
                break;
            }

            if (sendSize == 0)
                continue;

            /* Send the response buffer to the server.. */
            auto result = sendto(socket->s, sendBuffer, sendSize, 0, (struct sockaddr*)&client, socksize);
            if (sendSize == 72 || result == SOCKET_ERROR || sendSize == -1)
            {
                xiloader::console::output("Server connection done; disconnecting!");
                xiloader::NotifyShutdown(sharedState);
                return;
            }

            sendSize = 0;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    /**
     * @brief Data communication between the local client and the lobby server.
     *
     * @param client        Pointer to Socket.
     *
     * @return void.
     */
    void network::PolDataComm(SOCKET* client, xiloader::SharedState& sharedState)
    {
        unsigned char recvBuffer[1024] = { 0 };
        int result = 0, x = 0;
        time_t t = 0;
        bool bIsNewChar = false;

        do
        {
            /* Attempt to receive incoming data.. */
            result = recv(*client, (char*)recvBuffer, sizeof(recvBuffer), 0);
            if (result <= 0 && sharedState.isRunning)
            {
                xiloader::console::output(xiloader::color::error, "Client recv failed: %d", WSAGetLastError());
                break;
            }

            char temp = recvBuffer[0x04];
            memset(recvBuffer, 0x00, 32);

            switch (x)
            {
            case 0:
                recvBuffer[0] = 0x81;
                t = time(NULL);
                memcpy(recvBuffer + 0x14, &t, 4);
                result = 24;
                break;

            case 1:
                if (temp != 0x28)
                    bIsNewChar = true;
                recvBuffer[0x00] = 0x28;
                recvBuffer[0x04] = 0x20;
                recvBuffer[0x08] = 0x01;
                recvBuffer[0x0B] = 0x7F;
                result = bIsNewChar ? 144 : 24;
                if (bIsNewChar) bIsNewChar = false;
                break;
            }

            /* Echo back the buffer to the server.. */
            if (send(*client, (char*)recvBuffer, result, 0) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Client send failed: %d", WSAGetLastError());
                break;
            }

            /* Increase the current packet count.. */
            x++;
            if (x == 3)
                break;

        } while (result > 0);
    }

    /**
     * @brief Starts the local listen server to lobby server communications.
     *
     * @param socket        Socket reference to accept communications.
     * @param client        Client Socket reference to listen on.
     * @param server        Lobby server port.
     * @param sharedState   Shared thread state (bool, mutex, condition_variable).
     *
     * @return void.
     */
    void network::PolServer(SOCKET& socket, SOCKET& client, const std::string& lobbyServerPort, xiloader::SharedState& sharedState)
    {
        /* Attempt to create listening server.. */
        if (!xiloader::network::CreateListenServer(&socket, IPPROTO_TCP, lobbyServerPort.c_str()))
        {
            xiloader::NotifyShutdown(sharedState);
            return;
        }

        std::thread thread_polDataComm;

        while (sharedState.isRunning)
        {
            /* Attempt to accept incoming connections.. */
            client = accept(socket, NULL, NULL);
            if (client == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::error, "Accept failed: %d", WSAGetLastError());
            }
            else
            {
                /* Start data communication for this client.. */
                PolDataComm(&client, sharedState);
                /* Shutdown the client socket.. */
                CleanupSocket(client, SD_RECEIVE);
            }
        }

        xiloader::console::output("PolServer connection done; disconnecting!");

        // Most likely already handled and the socket/client pointers are invalid
        // but the operation will not throw
        CleanupSocket(socket, SD_RECEIVE);
        CleanupSocket(client, SD_RECEIVE);

        return;
    }

    /**
     * @brief Cleans up a socket via shutdown/close.
     *
     * @param socket        Socket reference.
     * @param how           Shutdown send, recv, or both.
     *
     * @return void.
     */
    void xiloader::network::CleanupSocket(SOCKET& sock, int how)
    {
        shutdown(sock, how);
        closesocket(sock);
        sock = INVALID_SOCKET;
    }

}; // namespace xiloader
