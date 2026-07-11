#pragma once
#include "constants-defs.h"
#include "lattice/stdlatticeparms.h"
#include "openfhe.h"

// TODO: Make parameters shared with benchmarks and match benchmark values with unit tests
namespace spar::params {
/// @brief Create parameters shared by all tests
/// @todo More complex construction, and store common parameter sets
template <typename T = lbcrypto::CryptoContextBGVRNS>
inline lbcrypto::CCParams<T> Large() {
    lbcrypto::CCParams<T> params;

    // params.SetPlaintextModulus(65537);
    params.SetPlaintextModulus(1 << 8);
    params.SetRingDim(1 << 14);

    params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);
    params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);

    // Q = 120 bits
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

template <typename T = lbcrypto::CryptoContextBGVRNS>
inline lbcrypto::CCParams<T> Small(const bool hybrid = false) {
    lbcrypto::CCParams<T> params;

    params.SetPlaintextModulus(1 << 8);
    params.SetRingDim(1 << 12);

    params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);

    // Q = 120 bits
    params.SetFirstModSize(60);
    params.SetScalingModSize(60);
    params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);

    if(!hybrid) return params;

    // Hybrid should be default anyways
    params.SetKeySwitchTechnique(lbcrypto::HYBRID);
    params.SetNumLargeDigits(1);  // |P| ~= |Q|
    params.SetRingDim(1 << 13);

    return params;
}
}  // namespace spar::params