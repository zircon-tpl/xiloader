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

#ifndef __XILOADER_NETWORK_H_INCLUDED__
#define __XILOADER_NETWORK_H_INCLUDED__

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <string>
#include <conio.h>
#include <mutex>
#include <condition_variable>

#include "console.h"
#include "FFXi.h"

namespace xiloader
{
    // In VerifyAccount - response codes to login attempts
    enum class AccountResult
    {
        Login_Success = 0x001,
        Login_Error = 0x002,
        Create_Success = 0x003,
        Create_Taken = 0x004,
        Create_Disabled = 0x008,
        Create_Error = 0x009,
        PassChange_Request = 0x005,
        PassChange_Success = 0x006,
        PassChange_Error = 0x007,
    };
    /**
     * @brief Socket object used to hold various important information.
     */
    typedef struct datasocket_t
    {
        datasocket_t() : s(INVALID_SOCKET), AccountId(0), LocalAddress((ULONG)-1), ServerAddress((ULONG)-1)
        {}

        SOCKET s;
        UINT32 AccountId;
        ULONG LocalAddress;
        ULONG ServerAddress;
    } datasocket;

    /**
     * @brief State shared between operating threads (FFXI, POL, etc).
     */
    typedef struct SharedState {
        bool isRunning{ false };
        std::mutex mutex;
        std::condition_variable conditionVariable;
    } SharedState;

    /**
     * @brief Lock/Signal a system shutdown by modifying running state.
     *
     * @param sharedState   Shared thread state (bool, mutex, condition_variable).
     *
     * @return void.
     */
    static void NotifyShutdown(xiloader::SharedState& sharedState)
    {
        std::lock_guard<std::mutex> lock(sharedState.mutex);
        sharedState.isRunning = false;
        sharedState.conditionVariable.notify_all();
    }

    /**
     * @brief Network class containing functions related to networking.
     */
    class network
    {
        /**
         * @brief Data communication between the local client and the lobby server.
         *
         * @param client        Pointer to Socket.
         *
         * @return void.
         */
        static void PolDataComm(SOCKET* client);
        
    public:

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
        static void FFXiDataComm(xiloader::datasocket* socket, const std::string& server, char*& characterList, xiloader::SharedState& sharedState);

        /**
         * @brief Creates a connection on the given port.
         *
         * @param sock          The datasocket object to store information within.
         * @param server        Server address to connect.
         * @param port          The port to create the connection on.
         *
         * @return True on success, false otherwise.
         */
        static bool CreateConnection(datasocket* sock, const std::string& server, const char* port);

        /**
         * @brief Creates a listening server on the given port and protocol.
         *
         * @param sock          The socket object to bind to.
         * @param protocol      The protocol to use on the new listening socket.
         * @param port          The port to bind to listen on.
         *
         * @return True on success, false otherwise.
         */
        static bool CreateListenServer(SOCKET* sock, int protocol, const char* port);
        
        /**
         * @brief Resolves the given hostname to its long ip format.
         *
         * @param host          The host name to resolve.
         * @param lpOutput      Pointer to a ULONG to store the result.
         *
         * @return True on success, false otherwise.
         */
        static bool ResolveHostname(const char* host, PULONG lpOutput);

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
        static bool VerifyAccount(datasocket* sock, const std::string& server, std::string& username, std::string& password);

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
        static void PolServer(SOCKET& socket, SOCKET& client, const std::string& lobbyServerPort, xiloader::SharedState& sharedState);

        /**
         * @brief Cleans up a socket via shutdown/close.
         *
         * @param socket        Socket reference.
         * @param how           Shutdown send, recv, or both.
         *
         * @return void.
         */
        static void CleanupSocket(SOCKET& socket, int how);
    };

}; // namespace xiloader

#endif // __XILOADER_NETWORK_H_INCLUDED__
