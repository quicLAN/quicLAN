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
#include <endian.h>
// MsQuic headers define min/max macros. Undefine them.
#undef min
#undef max
#include <vector>
#include <list>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <random>
#include <atomic>
#include <chrono>
#include <thread>
#include <string.h>

#include "timer.h"
#include "messages.h"
#include "workitem.h"
#include "engine.h"
