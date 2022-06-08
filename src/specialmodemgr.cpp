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

#include "specialmodemgr.hpp"

#include <filesystem>
#include <sys/sysinfo.h>
#include <gpiod.hpp>
#include <grp.h>

#include <shadow.h>
#include <fstream>
#include <string>
#include <phosphor-logging/lg2.hpp>
#include <boost/process.hpp>

using std::operator""s;

namespace specialMode
{
static constexpr const char* specialModeMgrService =
    "xyz.openbmc_project.SpecialMode";
static constexpr const char* specialModeIntf =
    "xyz.openbmc_project.Security.SpecialMode";
static constexpr const char* specialModePath =
    "/xyz/openbmc_project/security/special_mode";
static constexpr const char* specialModeManagerIntf =
    "xyz.openbmc_project.Security.SpecialMode.Manager";
static constexpr const char* provisioningMode =
    "xyz.openbmc_project.Control.Security.RestrictionMode.Modes.Provisioning";
static constexpr const char* restrictionModeService =
    "xyz.openbmc_project.RestrictionMode.Manager";
static constexpr const char* restrictionModeIntf =
    "xyz.openbmc_project.Control.Security.RestrictionMode";

static constexpr const char* restrictionModeProperty = "RestrictionMode";
static constexpr int mtmAllowedTime = 15 * 60; // 15 minutes

using VariantValue =
    std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
                 uint64_t, double, std::string>;

namespace secCtrl = sdbusplus::xyz::openbmc_project::Control::Security::server;

#ifdef BMC_VALIDATION_UNSECURE_FEATURE

static bool executeCmd(const char* cmd)
{
    boost::process::child execProg(cmd);
    execProg.wait();
    int status = execProg.exit_code();
    if (status != 0)
    {
        lg2::error("Subprocess failed", "STATUS", status);
        return false;
    }
    return true;
}

/**
 * Enable or disable the root user login and administrative group privileges. If
 * user is already in the desired state, take no action and return false.
 *
 * User is considered enabled if their shadow password hash contains any data.
 * This would happen if the user was already configured through any means (e.g.
 * IPMI command).
 *
 * To enable the user, this function will make the password hash null and force
 * password expiration so that the user can login at the console without a
 * password but will be forced to set a new one at that time.
 *
 * To disable the user, this function will lock and delete the password so that
 * the password hash goes back to the original state, and appears to have never
 * been set.
 *
 * @return Whether we successfully modified the root user. False if modification
 *         was not necessary OR if modification failed.
 */
static bool enableSpecialUser(bool enable)
{
    std::array<char, 4096> sbuffer{};
    struct spwd spwd;
    struct spwd* resultPtr = nullptr;
    constexpr const char* specialUser = "root";

    // Query shadow entry for special user.
    // Use the library API since there is no utility that provides the hashed
    // password. Only other alternative is manual file IO on /etc/shadow.
    int status = getspnam_r(specialUser, &spwd, sbuffer.data(),
                            sbuffer.max_size(), &resultPtr);
    if (status || (&spwd != resultPtr))
    {
        lg2::error("Error in querying shadow entry for special user");
        return false;
    }
    std::string curPwHash(resultPtr->sp_pwdp);
    bool userEnabled = (curPwHash != "!" && curPwHash != "*");

    // Check if special user is alread in admin group.
    bool inGroup = false;
    while (group* groupEntry = getgrent())
    {
        if (groupEntry->gr_name == std::string_view("priv-admin"))
        {
            for (int i = 0; groupEntry->gr_mem[i] != nullptr; ++i)
            {
                const char* member = groupEntry->gr_mem[i];
                if (member == std::string_view(specialUser))
                {
                    inGroup = true;
                    break;
                }
            }
            break;
        }
    }

    const char *passwordCmd = nullptr, *groupCmd = nullptr;
    const bool changePassword = enable != userEnabled;
    const bool changeGroup = enable != inGroup;
    if (enable)
    {
        // Sets the password hash to "" and set date of last password change to
        // 0 so that user can log in but is forced to set a password.
        // see shadow(5) for more details
        passwordCmd = "/usr/bin/passwd --delete --expire root";
        groupCmd = "/usr/sbin/groupmems -g priv-admin -a root";
    }
    else
    {
        // Sets the password hash to "!" so that the account is locked, but can
        // be unlocked by entering a special mode again in the future.
        passwordCmd = "/usr/bin/passwd --delete --lock root";
        groupCmd = "/usr/sbin/groupmems -g priv-admin -d root";
    }

    if (changePassword && !executeCmd(passwordCmd))
    {
        lg2::error("Failed to modify root password");
        return false;
    }

    if (changeGroup && !executeCmd(groupCmd))
    {
        lg2::error("Failed to modify root administrative privileges");
        return false;
    }

    lg2::info("Configured special user sucessfully");
    return true;
}

static void
    startSSHServer(const std::shared_ptr<sdbusplus::asio::connection>& conn)
{
    auto startUnit = conn->new_method_call(
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "StartUnit");
    startUnit.append("dropbear.socket", "replace");
    try
    {
        conn->call(startUnit);
        lg2::info("Started SSH server");
    }
    catch (const sdbusplus::exception::SdBusError&)
    {
        lg2::error("Failed to start SSH server");
    }
}

#endif

SpecialModeMgr::SpecialModeMgr(
    boost::asio::io_service& io_, sdbusplus::asio::object_server& srv_,
    std::shared_ptr<sdbusplus::asio::connection>& conn_) :
    io(io_),
    server(srv_), conn(conn_),
    timer(std::make_unique<boost::asio::steady_timer>(io)),
    specialMode(secCtrl::SpecialMode::Modes::None)
{
#ifdef BMC_VALIDATION_UNSECURE_FEATURE
    evaluateValidationJumperMode();
    bool valModeFileExists = std::filesystem::exists(validationModeFile);
    // Only valJumper triggers extra actions of enabling root user and SSH
    // server.
    if (valJumperMode)
    {
        std::ofstream(valJumperFile).close();
        enableSpecialUser(true);
        // On repeat boots with jumper asserted, enableSpecialUser will return
        // false because it's already enabled, but we still want to start SSH
        // server.
        startSSHServer(conn);
    }
    else if (std::filesystem::exists(valJumperFile))
    {
        if (enableSpecialUser(false))
        {
            // Only if we successfully disabled the root user, delete the flag.
            std::filesystem::remove(valJumperFile);
        }
        // SSH is "disabled" by virtue of it not being manually started. But it
        // may actually be running still if user enabled the service while
        // jumper was asserted.
    }

    // But presence of either valModeFile or valJumper puts us into
    // ValidationUnsecure mode.
    if (valModeFileExists || valJumperMode)
    {
        specialMode = secCtrl::SpecialMode::Modes::ValidationUnsecure;
        lg2::critical("ValidationUnsecure mode - Entered", "REDFISH_MESSAGE_ID",
                      "OpenBMC.0.1.ManufacturingModeEntered"s);

        addSpecialModeProperty();

        // Don't bother checking for manufacturing mode if we've already entered
        // ValidationUnsecure mode.
        return;
    }
#endif

    // Following condition must match to indicate specialMode.
    // Mark the mode as None for any failure.
    // 1. U-Boot detected power button press & indicated "special=mfg"
    // in command line parameter.
    // 2. BMC in Provisioning mode.
    // 3. BMC boot is due to AC cycle.
    // 4. Not crossed 12 hours in this special case.
    std::string cmdLineStr;
    std::ifstream cmdLineIfs("/proc/cmdline");
    getline(cmdLineIfs, cmdLineStr);
    static constexpr const char* specialModeStr = "special=mfg";
    static constexpr const char* resetReasonStr = "resetreason";
    static constexpr const uint32_t acBootFlag = 0x1;
    static constexpr const char argDelim = ' ';
    static constexpr const char paramDelim = '=';
    bool enterSpecialMode = false;
    if (cmdLineStr.find(specialModeStr) != std::string::npos)
    {
        size_t pos = cmdLineStr.find(resetReasonStr);
        if (pos != std::string::npos)
        {
            std::string argStr =
                cmdLineStr.substr(pos, cmdLineStr.find(argDelim, pos) - pos);
            std::string paramStr = argStr.substr(argStr.find(paramDelim) + 1);
            try
            {
                uint32_t reasonVal = std::stoul(paramStr, 0, 16);
                if (reasonVal & acBootFlag)
                {
                    enterSpecialMode = true;
                }
            }
            catch (const std::invalid_argument& ia)
            {
                // Do nothing. Keep the enterSpecialMode as false.
            }
        }
    }

    if (enterSpecialMode)
    {
        intfAddMatchRule = std::make_unique<sdbusplus::bus::match::match>(
            static_cast<sdbusplus::bus::bus&>(*conn),
            "type='signal',member='InterfacesAdded',sender='" +
                std::string(restrictionModeService) + "'",
            [this](sdbusplus::message::message& message) {
                sdbusplus::message::object_path objectPath;
                std::map<std::string, std::map<std::string, VariantValue>>
                    objects;
                message.read(objectPath, objects);
                VariantValue mode;
                try
                {
                    std::map<std::string, VariantValue> prop =
                        objects.at(restrictionModeIntf);
                    mode = prop.at(restrictionModeProperty);
                }
                catch (const std::out_of_range& e)
                {
                    lg2::error("Error in finding RestrictionMode property");
                    return;
                }
                checkAndAddSpecialModeProperty(std::get<std::string>(mode));
            });

        propUpdMatchRule = std::make_unique<sdbusplus::bus::match::match>(
            static_cast<sdbusplus::bus::bus&>(*conn),
            "type='signal',member='PropertiesChanged', "
            "interface='org.freedesktop.DBus.Properties', "
            "arg0namespace='xyz.openbmc_project.Control.Security."
            "RestrictionMode'",
            [this](sdbusplus::message::message& message) {
                std::string intfName;
                std::map<std::string, std::variant<std::string>> properties;

                // Skip reading 3rd argument (old porperty value)
                message.read(intfName, properties);

                std::variant<std::string> mode;
                try
                {
                    mode = properties.at(restrictionModeProperty);
                }

                catch (const std::out_of_range& e)
                {
                    lg2::error("Error in finding RestrictionMode property");
                    return;
                }

                if (std::get<std::string>(mode) != provisioningMode)
                {
                    lg2::info("Mode is not provisioning");
                    setSpecialModeValue(secCtrl::SpecialMode::Modes::None);
                }
            });

        conn->async_method_call(
            [this](boost::system::error_code ec, const VariantValue& mode) {
                if (ec)
                {
                    lg2::info(
                        "Error in reading restrictionMode property, probably "
                        "service not up");
                    return;
                }
                checkAndAddSpecialModeProperty(std::get<std::string>(mode));
            },
            restrictionModeService,
            "/xyz/openbmc_project/control/security/restriction_mode",
            "org.freedesktop.DBus.Properties", "Get", restrictionModeIntf,
            restrictionModeProperty);
    }
    else
    {
        addSpecialModeProperty();
    }
}

void SpecialModeMgr::checkAndAddSpecialModeProperty(const std::string& provMode)
{
    if (iface != nullptr && iface->is_initialized())
    {
        // Already initialized
        return;
    }
    if (provMode != provisioningMode)
    {
        addSpecialModeProperty();
        return;
    }
    struct sysinfo sysInfo = {};
    int ret = sysinfo(&sysInfo);
    if (ret != 0)
    {
        lg2::info("ERROR in getting sysinfo", "RET", ret);
        addSpecialModeProperty();
        return;
    }
    int specialModeLockoutSeconds = 0;
    if (mtmAllowedTime > sysInfo.uptime)
    {
        specialMode = secCtrl::SpecialMode::Modes::Manufacturing;
        specialModeLockoutSeconds = mtmAllowedTime - sysInfo.uptime;
        lg2::info("Manufacturing mode - Entered", "REDFISH_MESSAGE_ID",
                  "OpenBMC.0.1.ManufacturingModeEntered"s);
#ifdef BMC_VALIDATION_UNSECURE_FEATURE
        enableSpecialUser(true);
#endif
    }
    addSpecialModeProperty();
    if (!specialModeLockoutSeconds)
    {
        return;
    }
    updateTimer(specialModeLockoutSeconds);
}

void SpecialModeMgr::addSpecialModeProperty()
{
    // Add path to server object
    iface = server.add_interface(specialModePath, specialModeIntf);
    iface->register_property(
        strSpecialMode, secCtrl::convertForMessage(specialMode),
        // Ignore set
        [this](const std::string& req, std::string& propertyValue) {
            secCtrl::SpecialMode::Modes mode =
                secCtrl::SpecialMode::convertModesFromString(req);
#ifdef BMC_VALIDATION_UNSECURE_FEATURE
            if ((mode == secCtrl::SpecialMode::Modes::ValidationUnsecure) &&
                (specialMode != mode))
            {
                std::ofstream output(validationModeFile);
                output.close();
                specialMode = mode;
                propertyValue = req;
                lg2::critical("ValidationUnsecure mode - Entered",
                              "REDFISH_MESSAGE_ID",
                              "OpenBMC.0.1.ManufacturingModeEntered"s);
                return 1;
            }
#endif

            if (mode == secCtrl::SpecialMode::Modes::None &&
                specialMode != mode)
            {
#ifdef BMC_VALIDATION_UNSECURE_FEATURE
                if (specialMode ==
                    secCtrl::SpecialMode::Modes::ValidationUnsecure)
                {
                    lg2::info("ValidationUnsecure mode - Exited",
                              "REDFISH_MESSAGE_ID",
                              "OpenBMC.0.1.ManufacturingModeExited"s);
                }
                std::filesystem::remove(validationModeFile);
#endif
                specialMode = mode;
                propertyValue = req;
                return 1;
            }
            return 0;
        },
        // Override get
        [this](const std::string& mode) {
            return secCtrl::convertForMessage(specialMode);
        });
    iface->register_method("ResetTimer", [this]() {
        if (specialMode == secCtrl::SpecialMode::Modes::Manufacturing)
        {
            updateTimer(mtmAllowedTime);
        }
        return;
    });

    iface->register_property("ValidationJumperMode", valJumperMode);
    iface->initialize(true);
}

void SpecialModeMgr::updateTimer(int countInSeconds)
{
    timer->expires_after(std::chrono::seconds(countInSeconds));
    timer->async_wait([this](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted)
        {
            // timer aborted
            return;
        }
        else if (ec)
        {
            lg2::error("Error in special mode timer");
            return;
        }
#ifdef BMC_VALIDATION_UNSECURE_FEATURE
        if (specialMode == secCtrl::SpecialMode::Modes::ValidationUnsecure)
        {
            // Don't reset, if in ValidationUnsecure mode
            return;
        }
#endif
        iface->set_property(
            strSpecialMode,
            secCtrl::convertForMessage(secCtrl::SpecialMode::Modes::None));
        lg2::info("Manufacturing mode - Exited", "REDFISH_MESSAGE_ID",
                  "OpenBMC.0.1.ManufacturingModeExited"s);
    });
}

#ifdef BMC_VALIDATION_UNSECURE_FEATURE
void SpecialModeMgr::evaluateValidationJumperMode()
{
    gpiod::line valJumperGpio = gpiod::find_line("FM_BMC_VAL_EN");
    if (!valJumperGpio) // jumper not supported on this platform
    {
        lg2::info("Validation mode jumper is not supported on this platform!");
        return;
    }
    try
    {
        valJumperGpio.request(
            {"special-mode-mgr", gpiod::line_request::DIRECTION_INPUT});
        valJumperMode = (valJumperGpio.get_value() > 0) ? true : false;
    }
    catch (const std::exception& e)
    {
        lg2::error("Unable to access GPIO.", "GPIO_NAME", valJumperGpio.name(),
                   "EX", std::string(e.what()));

        return;
    }
}
#endif

} // namespace specialMode

int main()
{
    using namespace specialMode;
    boost::asio::io_service io;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);
    conn->request_name(specialModeMgrService);
    sdbusplus::asio::object_server server(conn, true);
    auto mgrIntf =
        server.add_interface(specialModePath, specialModeManagerIntf);
    mgrIntf->initialize();
    server.add_manager(specialModePath);

    SpecialModeMgr specialModeMgr(io, server, conn);
    io.run();

    return 0;
}
