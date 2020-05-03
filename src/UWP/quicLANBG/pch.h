//
// pch.h
// Header for platform projection include files
//

#pragma once

#define WIN32_LEAN_AND_MEAN
//#include <Windows.h>
#include <winerror.h>
#include <sal.h>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.ApplicationModel.Background.h>
#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Storage.Streams.h>

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <stdexcept>

#include <msquichelper.h>

#include "quiclan.h"