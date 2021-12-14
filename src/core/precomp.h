/*
    Licensed under the MIT License.
*/
#pragma once

#include <quic_sal_stub.h>
#include <msquichelper.h>
#include <quiclan.h>

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

#include "auth.h"
#include "timer.h"
#include "messages.h"
#include "workitem.h"
#include "engine.h"
