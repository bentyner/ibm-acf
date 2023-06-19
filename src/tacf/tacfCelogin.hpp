#pragma once

#include <CeLogin.h>

#include <chrono>
#include <cstdint>
#include <string>

/**
 * TacfCelogin class for access control file (ACF) processing.
 * @brief ACF processing, celogin specific.
 */
class TacfCelogin
{
  public:
    /**
     * Authenticate against ACF using a password.
     * @brief ACF authentication.
     *
     * @param acf           A pointer to an ASN1 encoded binary ACF.
     * @param acfSize       The size of the ASN1 encoded binary ACF.
     * @param pubkey        A Pointer to a public key for validating the ACF.
     * @param pubkeySize    The size of the pulic key being provided.
     * @param password      Pointer to a password for authentication.
     * @param serial        Serial number of machine associated with the ACF.
     * @param replayId      Current and updated replay id value.
     *
     * @return A non-zero error value or zero on success.
     */
    int authenticate(const uint8_t* acf, const uint64_t acfSize,
                     const uint8_t* pubkey, const uint64_t pubkeySize,
                     const char* password, const std::string& serial,
                     uint64_t& replayId)
    {
        uint64_t timestamp = getTimestamp();

        CeLogin::AcfUserFields acfUserFields;

        // Authenticate with password.
        CeLogin::CeLoginRc authRc =
            CeLogin::checkAuthorizationAndGetAcfUserFieldsV2(
                acf, acfSize, password, strlen(password), timestamp, pubkey,
                pubkeySize, serial.data(), serial.size(), replayId,
                acfUserFields);

        // Return celogin specific error code.
        if (CeLogin::CeLoginRc::Success != authRc)
        {
            return authRc;
        }

        // Or success.
        return 0;
    }

    /**
     * Install ACF and retrieve a the ACF type, replay id, expiration time. In
     * the case of ACF type admin-reset the ecrypted admin password associated
     * with the ACF will also be returned.
     * @brief ACF installation.
     *
     * @param acf           A pointer to an ASN1 encoded binary ACF.
     * @param acfSize       The size of the ASN1 encoded binary ACF.
     * @param pubkey        A Pointer to a public key for validating the ACF.
     * @param pubkeySize    The size of the pulic key being provided.
     * @param serial        Serial number of machine associated with the ACF.
     * @param auth          A user auth value to populate.
     * @param type          The ACF type value to populate.
     * @param expires       The ACF expiration time to populate.
     * @param expireDate    The ACF expiration date to populate.
     * @param replay        Current and updated replay id value.
     *
     * @return A non-zero error value or zero on success.
     */
    int install(const uint8_t* acf, const uint64_t acfSize,
                const uint8_t* pubkey, const uint64_t pubkeySize,
                const std::string& serial, std::string& auth,
                CeLogin::AcfType& type, uint64_t& expires,
                std::string& expireDate, uint64_t& replayId)
    {
        uint64_t replayIdNew;
        uint64_t timestamp = getTimestamp();

        // Verify signature and get ACF type.
        CeLogin::CeLoginRc authRc = CeLogin::verifyACFForBMCUploadV2(
            acf, acfSize, timestamp, pubkey, pubkeySize, serial.data(),
            serial.size(), replayId, replayIdNew, type, expires);

        // Return celogin specific error code.
        if (CeLogin::CeLoginRc::Success != authRc)
        {
            return authRc;
        }

        CeLogin::AcfUserFields acfUserFields;

        // If ACF was reset-admin type then populate admin auth code.
        if (CeLogin::AcfType::AcfType_AdminReset == type)
        {
            // Validate ACF and retrieve user field
            authRc = CeLogin::checkAuthorizationAndGetAcfUserFieldsV2(
                acf, acfSize, nullptr, 0, timestamp, pubkey, pubkeySize,
                serial.data(), serial.size(), replayIdNew, acfUserFields);

            // Return celogin specific error code.
            if (CeLogin::CeLoginRc::Success != authRc)
            {
                return authRc;
            }

            // Get the encrypted admin password as a string.
            auth = std::string(acfUserFields.mTypeSpecificFields
                                   .mAdminResetFields.mAdminAuthCode,
                               acfUserFields.mTypeSpecificFields
                                       .mAdminResetFields.mAdminAuthCode +
                                   acfUserFields.mTypeSpecificFields
                                       .mAdminResetFields.mAdminAuthCodeLength);
        }

        // Update the replay id.
        replayId = replayIdNew;

        // Get the ACF expiration details.
        CeLogin::AcfType ceLoginType = CeLogin::AcfType::AcfType_Invalid;
        CeLogin::AcfVersion version  = CeLogin::CeLoginInvalidVersion;
        bool hasReplay               = false;
        CeLogin::CeLogin_Date ceLoginDate;

        if (CeLogin::CeLoginRc::Success ==
            CeLogin::extractACFMetadataV2(acf, acfSize, timestamp, pubkey,
                                          pubkeySize, serial.data(),
                                          serial.size(), ceLoginType, expires,
                                          ceLoginDate, version, hasReplay))
        {
            // Get expiration date as string.
            expireDate = getDate(ceLoginDate);
        }

        // And return success.
        return 0;
    }

    /**
     * Verify the ACF and the the expiration time.
     * @brief ACF verification.
     *
     * @param acf           A pointer to an ASN1 encoded binary ACF.
     * @param acfSize       The size of the ASN1 encoded binary ACF.
     * @param pubkey        A Pointer to a public key for validating the ACF.
     * @param pubkeySize    The size of the pulic key being provided.
     * @param serial        Serial number of machine associated with the ACF.
     * @param expires       The ACF expiration time to populate.
     * @param expireDate    The ACF expiration date to populate.
     *
     * @return A non-zero error value or zero on success.
     */
    int verify(const uint8_t* acf, const uint64_t acfSize,
               const uint8_t* pubkey, const uint64_t pubkeySize,
               const std::string& serial, uint64_t& expires,
               std::string& expireDate)
    {
        uint64_t timestamp           = getTimestamp();
        CeLogin::AcfType ceLoginType = CeLogin::AcfType::AcfType_Invalid;
        CeLogin::AcfVersion version  = CeLogin::CeLoginInvalidVersion;
        bool hasReplay               = false;
        CeLogin::CeLogin_Date ceLoginDate;

        // Verify the ACF and get ACF expiration details.
        CeLogin::CeLoginRc authRc = CeLogin::extractACFMetadataV2(
            acf, acfSize, timestamp, pubkey, pubkeySize, serial.data(),
            serial.size(), ceLoginType, expires, ceLoginDate, version,
            hasReplay);

        // Return celogin specific error code.
        if (CeLogin::CeLoginRc::Success != authRc)
        {
            return authRc;
        }

        // Get expiration date as string.
        expireDate = getDate(ceLoginDate);

        // And return success.
        return 0;
    }

  private:
    /** @brief A helper function to get a current timestamp */
    uint64_t getTimestamp()
    {
        // Encode current system time as a unix timestamp.
        return std::chrono::duration_cast<std::chrono::seconds>(
                   (std::chrono::system_clock::now()).time_since_epoch())
            .count();
    }

    /** @brief A helper function to get expiration date as string */
    std::string getDate(CeLogin::CeLogin_Date ceLoginDate)
    {
        // Convert to expected format.
        std::string buffer(sizeof("yyyy-mm-dd\0"), ' ');
        sprintf(buffer.data(), "%04u-%02u-%02u", ceLoginDate.mYear,
                ceLoginDate.mMonth, ceLoginDate.mDay);
        buffer.resize(sizeof("yyyy-mm-dd"));

        return buffer;
    }
};
