#include "CliCeLoginV1.h"

#include "../celogin/src/CeLoginAsnV1.h"
#include "../celogin/src/CeLoginJson.h"
#include "../celogin/src/CeLoginUtil.h"
#include "CliUtils.h"
#include "openssl/obj_mac.h"
#include "openssl/objects.h"
#include "openssl/rsa.h"
#include "openssl/x509.h" // Needed for reading in public key

#include <CeLogin.h>
#include <json-c/json.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/sha.h>
#include <string.h>

#include <cinttypes>
#include <iostream>
#include <sstream>
#include <vector>

CeLogin::CeLoginRc
    CeLogin::createCeLoginAcfV1(const CeLoginCreateHsfArgsV1& argsParm,
                                std::vector<uint8_t>& generatedAcfParm)
{
    CeLoginRc sRc = CeLoginRc::Success;
    std::string sPasswordHashHexString;

    std::string sJsonString;
    std::vector<uint8_t> sJsonDigest(CeLogin::CeLogin_DigestLength);
    std::vector<uint8_t> sPasswordHash(CeLogin::CeLogin_PasswordHashLength);
    std::vector<uint8_t> sJsonSignature;

    CELoginSequenceV1* sHsfStruct = NULL;

    if (argsParm.mSourceFileName.empty() || argsParm.mMachines.empty() ||
        argsParm.mPassword.empty() || argsParm.mExpirationDate.empty() ||
        argsParm.mRequestId.empty())
    {
        sRc = CeLoginRc::Failure;
        std::cout << "ERROR line " << __LINE__ << std::endl;
    }

    // Hash password
    if (CeLoginRc::Success == sRc)
    {
        sRc = CeLogin::createPasswordHash(
            argsParm.mPassword.data(), argsParm.mPassword.size(),
            sPasswordHash.data(), sPasswordHash.size());
    }

    // Convert binary hash to Hex String
    if (CeLoginRc::Success == sRc)
    {
        sPasswordHashHexString = cli::getHexStringFromBinary(sPasswordHash);
    }

    // Create json structure
    if (CeLoginRc::Success == sRc)
    {
        json_object* sJsonObj = json_object_new_object();
        json_object* sVersion = json_object_new_int(CeLoginVersion1);
        json_object* sMachinesArray = json_object_new_array();

        json_object* sHashedPassword =
            json_object_new_string(sPasswordHashHexString.c_str());
        json_object* sExpirationDate =
            json_object_new_string(argsParm.mExpirationDate.c_str());
        json_object* sRequestId =
            json_object_new_string(argsParm.mRequestId.c_str());

        if (sJsonObj && sVersion && sMachinesArray && sHashedPassword &&
            sExpirationDate && sRequestId)
        {
            for (std::size_t sIdx = 0; sIdx < argsParm.mMachines.size(); sIdx++)
            {
                json_object* sMachinesObj = json_object_new_object();
                json_object* sSerialNumber = json_object_new_string(
                    argsParm.mMachines[sIdx].mSerialNumber.c_str());
                std::string sFrameworkEcStr;

                if (P10 == argsParm.mMachines[sIdx].mProc)
                {
                    if (ServiceAuth_Dev == argsParm.mMachines[sIdx].mAuth)
                    {
                        sFrameworkEcStr = FrameworkEc_P10_Dev;
                    }
                    else if (ServiceAuth_CE == argsParm.mMachines[sIdx].mAuth)
                    {
                        sFrameworkEcStr = FrameworkEc_P10_Service;
                    }
                }

                json_object* sFrameworkEc =
                    json_object_new_string(sFrameworkEcStr.c_str());

                if (sFrameworkEc && sSerialNumber && sMachinesObj)
                {
                    json_object_object_add(sMachinesObj, JsonName_SerialNumber,
                                           sSerialNumber);
                    json_object_object_add(sMachinesObj, JsonName_FrameworkEc,
                                           sFrameworkEc);
                    json_object_array_add(sMachinesArray, sMachinesObj);
                }
                else
                {
                    if (sMachinesObj)
                        json_object_put(sMachinesObj);
                    if (sFrameworkEc)
                        json_object_put(sFrameworkEc);
                    if (sSerialNumber)
                        json_object_put(sSerialNumber);
                    sRc = CeLoginRc::Failure;
                    break;
                }
            }

            json_object_object_add(sJsonObj, JsonName_Version, sVersion);
            json_object_object_add(sJsonObj, JsonName_Machines, sMachinesArray);
            json_object_object_add(sJsonObj, JsonName_HashedAuthCode,
                                   sHashedPassword);
            json_object_object_add(sJsonObj, JsonName_Expiration,
                                   sExpirationDate);
            json_object_object_add(sJsonObj, JsonName_RequestId, sRequestId);

            // When the json object is free'd this string will also be free'd
            const char* sGeneratedJsonString =
                json_object_to_json_string(sJsonObj);

            if (sGeneratedJsonString)
            {
                sJsonString = std::string(sGeneratedJsonString);
            }
            else
            {
                sRc = CeLoginRc::Failure;
            }
        }
        else
        {
            sRc = CeLoginRc::Failure;
        }

        if (CeLoginRc::Success != sRc)
        {
            // deallocate memory
            if (sJsonObj)
            {
                json_object_put(sJsonObj);
                sJsonObj = NULL;
            }
            if (sVersion)
            {
                json_object_put(sVersion);
                sVersion = NULL;
            }
            if (sMachinesArray)
            {
                json_object_put(sMachinesArray);
                sMachinesArray = NULL;
            }
            if (sHashedPassword)
            {
                json_object_put(sHashedPassword);
                sHashedPassword = NULL;
            }
            if (sExpirationDate)
            {
                json_object_put(sExpirationDate);
                sExpirationDate = NULL;
            }
            if (sRequestId)
            {
                json_object_put(sRequestId);
                sRequestId = NULL;
            }
        }

        if (sJsonObj)
        {
            json_object_put(sJsonObj);
            sJsonObj = NULL;
        }
    }

    if (CeLoginRc::Success == sRc && !sJsonString.empty())
    {
        sRc = createDigest((const uint8_t*)sJsonString.data(),
                           sJsonString.length(), sJsonDigest.data(),
                           sJsonDigest.size());
    }

    if (CeLoginRc::Success == sRc)
    {
        const uint8_t* sConstPrivateKey = argsParm.mPrivateKey.data();
        RSA* sPrivateKey = d2i_RSAPrivateKey(NULL, &sConstPrivateKey,
                                             argsParm.mPrivateKey.size());
        // TODO: Verify size matches expected size
        if (sPrivateKey)
        {
            unsigned int sJsonSignatureSize = sJsonSignature.size();
            sJsonSignature = std::vector<uint8_t>(RSA_size(sPrivateKey));
            int sResult = RSA_sign(CeLogin::CeLogin_Acf_NID, sJsonDigest.data(),
                                   sJsonDigest.size(), sJsonSignature.data(),
                                   &sJsonSignatureSize, sPrivateKey);
            if (1 != sResult)
            {
                sRc = CeLoginRc::Failure;
            }
            else if (sJsonSignatureSize != sJsonSignature.size())
            {
                sRc = CeLoginRc::Failure;
            }
        }

        if (sPrivateKey)
        {
            RSA_free(sPrivateKey);
        }
    }

    if (CeLoginRc::Success == sRc)
    {
        sHsfStruct = CELoginSequenceV1_new();

        ASN1_STRING_set(sHsfStruct->processingType, CeLogin::AcfProcessingType,
                        strlen(CeLogin::AcfProcessingType));
        ASN1_STRING_set(sHsfStruct->sourceFileName,
                        argsParm.mSourceFileName.c_str(),
                        argsParm.mSourceFileName.size());
        ASN1_OCTET_STRING_set(sHsfStruct->sourceFileData,
                              (const uint8_t*)sJsonString.data(),
                              sJsonString.size());
        sHsfStruct->algorithm->id = OBJ_nid2obj(CeLogin::CeLogin_Acf_NID);
        ASN1_BIT_STRING_set(sHsfStruct->signature, sJsonSignature.data(),
                            sJsonSignature.size());

        std::vector<uint8_t> sHsfDerEncoded(2000);
        uint8_t* sDataPtr = sHsfDerEncoded.data();
        uint64_t sHsfDerEncodedLength =
            i2d_CELoginSequenceV1(sHsfStruct, &sDataPtr);
        if (sHsfDerEncodedLength > 0)
        {
            // Remove extra data from vector
            sHsfDerEncoded.erase(sHsfDerEncoded.begin() + sHsfDerEncodedLength,
                                 sHsfDerEncoded.end());
            generatedAcfParm = sHsfDerEncoded;
        }
        else
        {
            sRc = CeLoginRc::Failure;
        }

        CELoginSequenceV1_free(sHsfStruct);
    }

    return sRc;
}

CeLogin::CeLoginRc CeLogin::decodeAndVerifyCeLoginHsfV1(
    const std::vector<uint8_t>& hsfParm,
    const std::vector<uint8_t>& publicKeyParm,
    CeLoginDecryptedHsfArgsV1& decodedHsfParm)
{
    CeLoginRc sRc = CeLoginRc::Success;

    CELoginSequenceV1* sDecodedAsn = NULL;

    if (CeLoginRc::Success == sRc)
    {
        sRc = decodeAndVerifyAcf(hsfParm.data(), hsfParm.size(),
                                 publicKeyParm.data(), publicKeyParm.size(),
                                 sDecodedAsn);
    }

    if (CeLoginRc::Success == sRc)
    {
        decodedHsfParm.mProcessingType =
            std::string((const char*)sDecodedAsn->processingType->data,
                        sDecodedAsn->processingType->length);
        decodedHsfParm.mSourceFileName =
            std::string((const char*)sDecodedAsn->sourceFileName->data,
                        sDecodedAsn->sourceFileName->length);
    }

    if (CeLoginRc::Success == sRc)
    {
        std::cout << std::string((char*)sDecodedAsn->sourceFileData->data,
                                 sDecodedAsn->sourceFileData->length)
                  << std::endl;
        json_object* sJson =
            json_tokener_parse((const char*)sDecodedAsn->sourceFileData->data);

        if (!sJson)
        {
            sRc = CeLoginRc::DecodeHsf_JsonParseFailure;
        }

        int32_t sVersion = 0;
        if (CeLoginRc::Success == sRc &&
            cli::getIntFromJson(sJson, CeLogin::JsonName_Version, sVersion))
        {
            if (CeLoginVersion1 != sVersion)
            {
                sRc = CeLoginRc::DecodeHsf_VersionMismatch;
            }
        }

        if (CeLoginRc::Success == sRc)
        {
            json_object* sMachinesArray = NULL;
            json_object* sMachinesObj = NULL;
            bool sMachineResult = json_object_object_get_ex(
                sJson, CeLogin::JsonName_Machines, &sMachinesArray);
            if (sMachineResult && sMachinesArray)
            {
                const size_t sArrayLength =
                    json_object_array_length(sMachinesArray);
                for (size_t sIdx = 0; sIdx < sArrayLength; sIdx++)
                {
                    sMachinesObj =
                        json_object_array_get_idx(sMachinesArray, sIdx);
                    if (sMachinesObj)
                    {
                        DecodedMachine sMachineEntry;
                        if (CeLoginRc::Success == sRc &&
                            !cli::getStringFromJson(
                                sMachinesObj, CeLogin::JsonName_SerialNumber,
                                sMachineEntry.mSerialNumber))
                        {
                            sRc = CeLoginRc::DecodeHsf_ReadSerialNumberFailure;
                        }
                        if (CeLoginRc::Success == sRc &&
                            !cli::getStringFromJson(
                                sMachinesObj, CeLogin::JsonName_FrameworkEc,
                                sMachineEntry.mFrameworkEc))
                        {
                            sRc = CeLoginRc::DecodeHsf_ReadFrameworkEcFailure;
                        }
                        if (CeLoginRc::Success == sRc)
                        {
                            decodedHsfParm.mMachines.push_back(sMachineEntry);
                        }
                        else
                        {
                            break;
                        }
                    }
                }
            }
            else
            {
                sRc = CeLoginRc::DecodeHsf_ReadMachineArrayFailure;
            }
        }

        if (CeLoginRc::Success == sRc &&
            !cli::getStringFromJson(sJson, CeLogin::JsonName_HashedAuthCode,
                                    decodedHsfParm.mPasswordHash))
        {
            sRc = CeLoginRc::DecodeHsf_ReadHashedAuthCodeFailure;
        }

        if (CeLoginRc::Success == sRc &&
            !cli::getStringFromJson(sJson, CeLogin::JsonName_Expiration,
                                    decodedHsfParm.mExpirationDate))
        {
            sRc = CeLoginRc::DecodeHsf_ReadExpirationFailure;
        }

        if (CeLoginRc::Success == sRc &&
            !cli::getStringFromJson(sJson, CeLogin::JsonName_RequestId,
                                    decodedHsfParm.mRequestId))
        {
            sRc = CeLoginRc::DecodeHsf_ReadRequestIdFailure;
        }

        if (sJson)
        {
            json_object_put(sJson);
        }
    }

    if (sDecodedAsn)
    {
        CELoginSequenceV1_free(sDecodedAsn);
    }
    return sRc;
}
