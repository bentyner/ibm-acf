#pragma once

#include "tacfCelogin.hpp"
#include "tacfDbus.hpp"
#include "tacfSpw.hpp"
#include "targetedAcf.hpp"

#include <array>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

constexpr unsigned int TargetedAcf::acfTypeInvalid =
    CeLogin::AcfType::AcfType_Invalid;

constexpr unsigned int TargetedAcf::acfTypeAdminReset =
    CeLogin::AcfType::AcfType_AdminReset;

constexpr unsigned int TargetedAcf::acfTypeService =
    CeLogin::AcfType::AcfType_Service;

const auto pubkeysProd = std::to_array<std::string>(
    {"/srv/ibm-acf/ibmacf-prod.key", "/srv/ibm-acf/ibmacf-prod-backup.key",
     "/srv/ibm-acf/ibmacf-prod-backup2.key"});

const auto pubkeysDev =
    std::to_array<std::string>({"/srv/ibm-acf/ibmacf-dev.key"});

constexpr auto acfFilePath = "/etc/acf/service.acf";

constexpr auto replayFilePath = "/etc/acf/acfv2.replay";

constexpr auto serialNumberEmpty = "       ";

constexpr auto serialNumberUnset = "UNSET";

// Function pointers for optional alternate functions.
typedef void (*logging_function)(std::string);
typedef void (*logging_function_pam)(void*, std::string);
typedef int (*field_mode_function_pam)(void*);

/**
 * Tacf class for implementing targeted ACF feature.
 *
 * Constructor example for logging with phosphor::logging
 *
 *   Tacf tacf{[](std::string msg) {
 *        log<phosphor::logging::level::INFO>(msg.c_str());
 *   }};
 *
 * Constructor example for logging with pam_syslog
 *
 *   Tacf tacf{[](void* pamh, std::string msg) {
 *        pam_syslog((pam_handle_t*)pamh, LOG_WARNING, "%s",
 *        msg.c_str());
 *   }, pamh};
 *
 *
 */
class Tacf : TargetedAcf
{
  public:
    Tacf(logging_function logger = nullptr) : logger(logger) {}

    Tacf(logging_function_pam logger, void* handle) :
        loggerPam(logger), pamHandle(handle)
    {}

    Tacf(logging_function_pam logger, field_mode_function_pam fieldmode,
         void* handle) :
        loggerPam(logger),
        fieldModePam(fieldmode), pamHandle(handle)
    {}

    /**
     * Authenticate against an ACF using a password.
     * @brief Authenticate using password.
     *
     * @param password  A pointer to a password used for authentication.
     *
     * @return A non-zero error value or zero on success.
     */
    int authenticate(const char* password)
    {
        if (!password)
        {
            return tacfAuthError;
        }

        std::vector<uint8_t> acf;
        if (readFile(acfFilePath, acf))
        {
            return tacfSystemError;
        }

        std::string expires;
        int rc = TargetedAcf::targetedAuth(
            acf.data(), acf.size(), expires,
            TargetedAcf::TargetedAcfAction::Authenticate, password);
        log("acfv2-authenticate-%0x", rc);
        return rc;
    }

    /**
     * Install ACF and retrieve expiration data.
     * @brief Install ACF.
     *
     * @param acf       A pointer to an ASN1 encoded binary ACF.
     * @param acfSize   The size of the ASN1 encoded binary ACF.
     *
     * @return A non-zero error value or zero on success.
     */
    int install(const uint8_t* acf, size_t acfSize, std::string& expires)
    {
        if (!acf || !acfSize)
        {
            return tacfAuthError;
        }

        // password (nullptr) not used for ACF install
        int rc = TargetedAcf::targetedAuth(
            acf, acfSize, expires, TargetedAcf::TargetedAcfAction::Install,
            nullptr);
        log("acfv2-install-%0x", rc);
        return rc;
    }

    /**
     * Verify ACF and retrieve expiration data.
     * @brief Verify ACF.
     *
     * @param acf       A pointer to an ASN1 encoded binary ACF.
     * @param acfSize   The size of the ASN1 encoded binary ACF.
     *
     * @return A non-zero error value or zero on success.
     */
    int verify(const uint8_t* acf, size_t acfSize, std::string& expires)
    {
        if (!acf || !acfSize)
        {
            return tacfAuthError;
        }

        int rc = TargetedAcf::targetedAuth(
            acf, acfSize, expires, TargetedAcf::TargetedAcfAction::Verify,
            nullptr);
        log("acfv2-verify-%0x", rc);
        return rc;
    }

    static constexpr int tacfSuccess     = 0;
    static constexpr int tacfFail        = 1;
    static constexpr int tacfSystemError = 0x10001;
    static constexpr int tacfAuthError   = 0x10002;

  private:
    /** @brief Optional logging support to register */
    logging_function logger              = nullptr;
    logging_function_pam loggerPam       = nullptr;
    field_mode_function_pam fieldModePam = nullptr;
    void* pamHandle                      = nullptr;

    /**
     * Process an ACF. Depending on the action requested and the type of
     * ACF presented this operation will result in one or more of the
     * following: validate ACF signature and structure, retrieve an
     * associated user auth code, retrieve the ACF expiration date,
     * retrieve an updated replay id.
     * @brief Process an ACF.
     *
     * @param acf       A pointer to an ASN1 encoded binary ACF.
     * @param acfSize   The size of the ASN1 encoded binary ACF.
     * @param auth      The user auth value to populate.
     * @param type      The ACF type value to populate.
     * @param expires   The ACF expiration date to populate.
     * @param replayId  The current and updated replay id value.
     * @param action    The type of action to perform with the ACF.
     * @param password  A pointer to a password for authentication.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int getAuth(const uint8_t* acf, size_t acfSize, std::string& auth,
                        unsigned int& type, std::string& expires,
                        uint64_t& replayId,
                        TargetedAcf::TargetedAcfAction action,
                        const char* password) final override
    {
        // Get serial number.
        std::string serial;
        if (retrieveSerial(serial))
        {
            return tacfFail;
        }

        // Get list of public keys to check signature against.
        std::vector<std::string> keyring;
        copy(begin(pubkeysProd), end(pubkeysProd), back_inserter(keyring));

        // If field mode disabled then also use development public key(s).
        bool fieldMode = true;
        if (!retrieveFieldMode(fieldMode) && !fieldMode)
        {
            copy(begin(pubkeysDev), end(pubkeysDev), back_inserter(keyring));
        }

        // Process ACF using auth provider with each key.
        TacfCelogin authProvider;
        int authRc = CeLogin::CeLoginRc::Failure;

        for (auto pathname : keyring)
        {
            // Skip key if file does not exist or is empty.
            std::vector<uint8_t> pubkey;
            if (readFile(pathname, pubkey) || pubkey.empty())
            {
                continue;
            }

            int authRc;
            uint64_t expireTime = 0;

            // If action is verify.
            if (TargetedAcf::TargetedAcfAction::Verify == action)
            {
                // Verify ACF.
                authRc = authProvider.verify(acf, acfSize, pubkey.data(),
                                             pubkey.size(), serial, expireTime,
                                             expires);
            }
            // Or if action is install.
            else if (TargetedAcf::TargetedAcfAction::Install == action)
            {
                CeLogin::AcfType ceLoginAcfType =
                    CeLogin::AcfType::AcfType_Invalid;

                // Install ACF.
                authRc = authProvider.install(
                    acf, acfSize, pubkey.data(), pubkey.size(), serial, auth,
                    ceLoginAcfType, expireTime, expires, replayId);

                // Convert from celogin ACF type to targeted ACF type.
                type = translateAcfType(ceLoginAcfType);
            }
            else
            {
                // Otherwise authenticate with password.
                authRc = authProvider.authenticate(acf, acfSize, pubkey.data(),
                                                   pubkey.size(), password,
                                                   serial, replayId);
            }

            // If action successful.
            if (CeLogin::CeLoginRc::Success == authRc)
            {
                // Get expiration date

                // And return success.
                return tacfSuccess;
            }
        }
        // Or return error code.
        return authRc;
    }

    /**
     * Retrieve a previously stored replay id.
     * @brief Retrieve replay id.
     *
     * @param id    A replay id value to populate.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int retrieveReplayId(uint64_t& id) final override
    {
        if (TacfDbus().readReplayId(id))
        {
            log("acfv2 retrieve replay error");
            return tacfSystemError;
        }

        return tacfSuccess;
    }

    /**
     * Store a new replay id overwriting existing replay id.
     * @brief Store replay id.
     *
     * @param id        A replay id value to store.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int storeReplayId(uint64_t id) final override
    {
        if (TacfDbus().writeReplayId(id))
        {
            log("acfv2 store replay error");
            return tacfSystemError;
        }

        return tacfSuccess;
    }

    /**
     * Reset the admin user account.
     * @brief Reset admin.
     *
     * @param spw  The value to use for admin user shadow password.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int resetAdmin(const std::string& spw) final override
    {
        if (TacfSpw().resetAdmin(spw))
        {
            log("acfv2 reset error");
            return tacfSystemError;
        }

        return tacfSuccess;
    }

    /**
     * Remove the previously installed ACF.
     * @brief Remove ACF.
     */
    virtual void removeAcf() override
    {
        std::remove(acfFilePath);
    }

    /**
     * Install the new ACF.
     * @brief Install ACF.
     *
     * @param acf       A pointer to an ASN1 encoded binary ACF.
     * @param size      The size of the ASN1 encoded binary ACF.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int installAcf(const uint8_t* acf, size_t size)
    {
        if (!acf || !size)
        {
            log("acfv2 install error");
            return tacfFail;
        }

        return writeFile(acf, size, acfFilePath);
    }

    /**
     * Retrieve the serial number of the system.
     * @brief retrieve serial number.
     *
     * @param serial    serial number value to populate.
     *
     * @return a non-zero error value or zero on success.
     */
    virtual int retrieveSerial(std::string& serial) const
    {
        if (TacfDbus().retrieveSerialNumber(serial))
        {
            log("acfv2 retrieve serial error");
            return tacfSystemError;
        }
        else
        {
            // Convert empty serial number to ACF form.
            if (serial.empty() || serialNumberEmpty == serial)
            {
                serial = serialNumberUnset;
            }
        }

        return tacfSuccess;
    }

    /**
     * Determined if system is operating in field mode.
     * @brief Retrieve field mode state.
     *
     * @param fieldMode Field mode enabled state to populate.
     *
     * @return A non-zero error value or zero on success.
     */
    virtual int retrieveFieldMode(bool& fieldMode) const
    {
        // If alternate get field mode registered.
        if (nullptr != fieldModePam)
        {
            // Use alternate method.
            int mode = fieldModePam(pamHandle);
            switch (mode)
            {
                case 0:
                    fieldMode = false;
                    break;
                case 1:
                    fieldMode = true;
                    break;
                default:
                    fieldMode = true;
                    log("acfv2 pam retrieve field error");
                    return tacfSystemError;
            }
        }
        // Otherwise use default method.
        else if (TacfDbus().retrieveFieldMode(fieldMode))
        {
            log("acfv2 retrieve field error");
            return tacfSystemError;
        }

        return tacfSuccess;
    }

    /**
     * Read a file in into a vector of bytes.
     * @brief Read a binary file.
     *
     * @param pathname  The path and name of the file to read.
     * @param buffer    The vector to read the file into.
     *
     * @return A non-zero error value or zero on success.
     */
    int readFile(const std::string& pathname,
                 std::vector<uint8_t>& buffer) const
    {
        std::ifstream file(pathname, std::ios::binary);
        file.unsetf(std::ios::skipws);

        if (!file)
        {
            log("acfv2 read file error");
            return tacfSystemError;
        }
        try
        {
            std::copy(std::istream_iterator<uint8_t>(file),
                      std::istream_iterator<uint8_t>(),
                      std::back_inserter(buffer));
        }
        catch (std::exception& e)
        {
            log("acfv2 read file exception");
            return tacfSystemError;
        }

        return tacfSuccess;
    }

    /**
     * Write a vector of bytes to a file.
     * @brief Write a binary file.
     *
     * @param buffer    A pointer to an ASN1 encoded binary ACF.
     * @param size      The size of the ASN1 encoded binary ACF.
     * @param pathname  The path and name of the file to write.
     *
     * @return A non-zero error value or zero on success.
     */
    int writeFile(const uint8_t* buffer, const size_t size,
                  const std::string& pathname) const
    {
        std::ofstream file(pathname, std::ios::trunc | std::ios::binary);

        if (!file)
        {
            log("acfv2 write file error");
            return tacfSystemError;
        }

        file.write((const char*)buffer, size);

        return tacfSuccess;
    }

    /** @brief Helper function for logging */
    void inf(const char* format, va_list args) const
    {
        char msg[255];
        vsnprintf(msg, 255, format, args);
        std::string msgString(msg);
        if (logger)
        {
            logger(msgString);
        }
        else if (loggerPam && pamHandle)
        {
            loggerPam(pamHandle, msgString);
        }
    }

    /** @brief Helper function for formatted logging */
    void log(const char* format, ...) const
    {
        if (!logger && !loggerPam)
        {
            return;
        }
        va_list args;
        va_start(args, format);
        inf(format, args);
        va_end(args);
    }

    /** @brief A helper function to convert between acf types */
    unsigned int translateAcfType(CeLogin::AcfType type)
    {
        unsigned int tacfType;

        switch (type)
        {
            case CeLogin::AcfType::AcfType_AdminReset:
                tacfType = TargetedAcf::acfTypeAdminReset;
                break;

            case CeLogin::AcfType::AcfType_Service:
                tacfType = TargetedAcf::acfTypeService;
                break;

            default:
                tacfType = TargetedAcf::acfTypeInvalid;
        }

        return tacfType;
    }
};
