/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once

#include <boost/asio/io_service.hpp>
#include <boost/asio/steady_timer.hpp>

#include <sdbusplus/asio/object_server.hpp>
#include <chrono>
#include <filesystem>
#include <xyz/openbmc_project/Control/Security/SpecialMode/server.hpp>

namespace specialMode
{
static constexpr const char* strSpecialMode = "SpecialMode";

class SpecialModeMgr
{
    boost::asio::io_service& io;
    sdbusplus::asio::object_server& server;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface;
    sdbusplus::xyz::openbmc_project::Control::Security::server::SpecialMode::
        Modes specialMode;
    std::unique_ptr<boost::asio::steady_timer> timer = nullptr;
    std::unique_ptr<sdbusplus::bus::match::match> intfAddMatchRule = nullptr;
    std::unique_ptr<sdbusplus::bus::match::match> propUpdMatchRule = nullptr;
    /**
     * Path to file (consumed by this service at startup) that signals
     * validation mode should be entered.
     */
    const std::filesystem::path validationModeFile =
        "/var/validation_unsecure_mode";
    /**
     * Path to file (created and consumed by the service) indicating that
     * special features were enabled due to jumper assertion and should be
     * disabled if jumper is no longer set.
     */
    const std::filesystem::path valJumperFile =
        "/var/val_jumper_assert_cleanup_required";
    void addSpecialModeProperty();
    void checkAndAddSpecialModeProperty(const std::string& provMode);
    void updateTimer(int countInSeconds);
#ifdef BMC_VALIDATION_UNSECURE_FEATURE
    void evaluateValidationJumperMode();
#endif
    bool valJumperMode = false;

  public:
    void setSpecialModeValue(
        const sdbusplus::xyz::openbmc_project::Control::Security::server::
            SpecialMode::Modes value) const
    {
        if (iface != nullptr && iface->is_initialized())
        {
            iface->set_property(strSpecialMode,
                                sdbusplus::xyz::openbmc_project::Control::
                                    Security::server::convertForMessage(value));
        }
    }
    SpecialModeMgr(boost::asio::io_service& io,
                   sdbusplus::asio::object_server& srv,
                   std::shared_ptr<sdbusplus::asio::connection>& conn);
};
} // namespace specialMode
