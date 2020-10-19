/*
    Licensed under the MIT License.
*/
#pragma once

#include <quic_sal_stub.h>
#include <msquichelper.h>
#include <quiclan.h>

// These will need to be moved into a platform abstraction layer
#include <netinet/ip.h>
#include <netinet/ip6.h>

#undef min
#undef max
#include <vector>
#include <mutex>
#include <condition_variable>
#include <string.h>

#include "engine.h"
