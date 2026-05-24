/**
 * @file common.h
 * @brief This file contains helpers used by all the tests
 */
#pragma once

#include <gtest/gtest.h>
#include "cli_params.h"
#include "openfhe.h"

// DEBUG_TIMING / DEBUG_LOGGING are opt-in via `DEBUG=1 make test-<name>`,
// which configures core_lib with PUBLIC compile defs that also reach tests.
#include "utils/timer.h"
#include "utils/logging.h"

// TODO: Make parameters shared with benchmarks and match benchmark values with unit tests
namespace params {
    /// @brief Create parameters shared by all tests
    /// @todo More complex construction, and store common parameter sets
    template<typename T>
    inline lbcrypto::CCParams<T> Large(const uint32_t depth = 1) {
        lbcrypto::CCParams<T> params;
        params.SetMultiplicativeDepth(depth);
        params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
        params.SetRingDim(test_cli::g_ring_dim.value_or(1 << 14));

        params.SetKeySwitchTechnique(lbcrypto::HYBRID); 
        params.SetNumLargeDigits(1);

        if(depth > 1)
            params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);
        
        // From sPAR
        double sigma = std::pow(2.0, -55.0);
        params.SetStandardDeviation(sigma);

        return params;
    }

    template<typename T = lbcrypto::CryptoContextBGVRNS>
    inline lbcrypto::CCParams<T> Small(const uint32_t depth = 1) {
        lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS> params;
        params.SetMultiplicativeDepth(depth);
        params.SetPlaintextModulus(1 << 8);
        params.SetRingDim(1 << 11);

        params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);
        
        // Hybrid should be default
        // params.SetKeySwitchTechnique(lbcrypto::HYBRID); 
        // params.SetNumLargeDigits(1); // Force |P| ~= |Q|
        
        // Debugging
        // params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);
        // params.SetFirstModSize(60);
        // params.SetScalingModSize(55);
        // params.SetStandardDeviation(.0f);

        // From sPAR
        double sigma = std::pow(2.0, -55.0);
        params.SetStandardDeviation(sigma);

        // params.SetSecretKeyDist(lbcrypto::SecretKeyDist::UNIFORM_TERNARY);

        return params;
    }
}