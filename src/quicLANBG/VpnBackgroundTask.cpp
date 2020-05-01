#include "pch.h"
#include "VpnBackgroundTask.h"
#include "VpnPlugin.h"

using namespace winrt;
using namespace Windows::ApplicationModel::Core;

namespace winrt::quicLANBG::implementation
{
	void VpnBackgroundTask::Run(Windows::ApplicationModel::Background::IBackgroundTaskInstance const& taskInstance)
	{
		auto deferral = taskInstance.GetDeferral();
		try
		{
			hstring pluginId{ L"quicLANPlugin" };

			IInspectable plugin;
			if (CoreApplication::Properties().HasKey(pluginId))
			{
				plugin = CoreApplication::Properties().Lookup(pluginId);
			}
			else
			{
				plugin = make<VpnPlugin>();
				CoreApplication::Properties().Insert(pluginId, plugin);
			}

			Windows::Networking::Vpn::VpnChannel::ProcessEventAsync(plugin, taskInstance.TriggerDetails());
		}
		catch (winrt::hresult_error const&)
		{
		}
		deferral.Complete();
	}
}
