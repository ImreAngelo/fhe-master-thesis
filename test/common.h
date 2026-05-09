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
    inline lbcrypto::CCParams<T> Create() {
        lbcrypto::CCParams<T> params;
        params.SetMultiplicativeDepth(1);
        params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
        params.SetRingDim(test_cli::g_ring_dim.value_or(1 << 14));
        
        // Tuneable parameter
        // params.SetNumLargeDigits(2);

        // RGSW rows are built by hand; requires FIXEDMANUAL or FIXEDAUTO
        params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(lbcrypto::FIXEDMANUAL));

        return params;
    }

    template<typename T>
    inline lbcrypto::CCParams<T> Small() {
        lbcrypto::CCParams<T> params;
        params.SetMultiplicativeDepth(4);
        params.SetPlaintextModulus(256);
        params.SetRingDim(1 << 11);

        // RGSW rows are built by hand; requires FIXEDMANUAL or FIXEDAUTO
        params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);
        params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);

        return params;
    }
}