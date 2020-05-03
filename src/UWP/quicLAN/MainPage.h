//
// Declaration of the MainPage class.
//

#pragma once

#include "MainPage.g.h"

namespace winrt::quicLAN::implementation
{
    struct MainPage : MainPageT<MainPage>
    {
        MainPage();

        void LaunchVPNSettings(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::RoutedEventArgs const& args);
        Windows::Foundation::IAsyncAction SaveVPN(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::RoutedEventArgs const& args);
        Windows::Foundation::IAsyncAction ConnectVPN(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::RoutedEventArgs const& args);
        Windows::Foundation::IAsyncAction DisconnectVPN(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::RoutedEventArgs const& args);

    private:
        void LoadSettings();
        void SaveSettings();
    };
}

namespace winrt::quicLAN::factory_implementation
{
    struct MainPage : MainPageT<MainPage, implementation::MainPage>
    {
    };
}
