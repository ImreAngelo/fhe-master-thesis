#pragma once
#include "constants-defs.h"
#include "lattice/stdlatticeparms.h"
#include "openfhe.h"

// TODO: Make parameters shared with benchmarks and match benchmark values with unit tests
namespace spar::params {
/// @brief Supports SIMD
/// @todo More complex construction, and store common parameter sets
template <typename T = lbcrypto::CryptoContextBGVRNS>
inline lbcrypto::CCParams<T> Large() {
    lbcrypto::CCParams<T> params;

    params.SetPlaintextModulus(65537);
    params.SetRingDim(1 << 14);

    params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);
    params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);

    // Q = 180 bits
    params.SetMultiplicativeDepth(3);
    params.SetFirstModSize(60);
    params.SetScalingModSize(60);

    // For GHS
    params.SetKeySwitchTechnique(lbcrypto::HYBRID);
    params.SetNumLargeDigits(1);

    // Debugging
    // double sigma = std::pow(2.0, -55.0);
    // params.SetStandardDeviation(sigma);

    return params;
}

/// @brief Match sPAR paper parameters
template <typename T = lbcrypto::CryptoContextBGVRNS>
inline lbcrypto::CCParams<T> Small(const bool hybrid = false) {
    lbcrypto::CCParams<T> params;

    params.SetPlaintextModulus(1 << 8);
    params.SetRingDim(1 << 12);

    params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);
    params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);

    // k = depth + 1
    params.SetMultiplicativeDepth(2);

    // Q = 64 bits
    params.SetFirstModSize(24);
    params.SetScalingModSize(20);

    // Q = 64 bits
    params.SetStandardDeviation(1.5);

    if(!hybrid) return params;

    // Hybrid should be enabled by default anyways
    params.SetKeySwitchTechnique(lbcrypto::HYBRID);
    params.SetNumLargeDigits(1);  // |P| ~= |Q|
    params.SetRingDim(1 << 13);   // Larger ring for hybrid to support larger QP modulus

    return params;
}
}  // namespace spar::params


// Best so far:
// params.SetPlaintextModulus(1 << 8);
// params.SetRingDim(1 << 12);

// params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);
// params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);

// // k = depth + 1
// params.SetMultiplicativeDepth(2);

// // Q = 120 bits
// params.SetFirstModSize(60);
// params.SetScalingModSize(30);