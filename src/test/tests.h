/*
    Licensed under the MIT License.
*/

#include <quic_sal_stub.h>
#include <msquichelper.h>
#include <quiclan.h>
#undef min
#undef max

// These will have to be replaced to be platform indepdendent
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <chrono>
#include <string>
#include <mutex>
#include <condition_variable>
#include <stdio.h>

//==================//
// End to end tests //
//==================//

/*
    A basic test that just starts a client and server and connects and send a datagram packet through.
*/
bool
TestBasicConnection();

//============//
// Unit tests //
//============//

/*
    Uses the Message header functions to generate a valid message header
    and then parses that header and ensures both succeed.
*/
bool
TestMessageGenerateParse();

/*
    Tests that the message header parser correctly fails invalid message headers.
*/
bool
TestMessageParseFail();
