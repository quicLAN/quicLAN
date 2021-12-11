/*
    Licensed under the MIT License.
*/

#include <quic_sal_stub.h>
#include <msquichelper.h>
#include <quiclan.h>
#undef min
#undef max

#include <gtest/gtest.h>

// These will have to be replaced to be platform indepdendent
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <chrono>
#include <string>
#include <mutex>
#include <condition_variable>
#include <stdio.h>
