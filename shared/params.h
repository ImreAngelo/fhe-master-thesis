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

    params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);
    params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);

    // For GHS
    params.SetKeySwitchTechnique(lbcrypto::HYBRID);
    params.SetNumLargeDigits(1);

    // From sPAR
    // double sigma = std::pow(2.0, -55.0);
    // params.SetStandardDeviation(sigma);

    return params;
}

template <typename T = lbcrypto::CryptoContextBGVRNS>
inline lbcrypto::CCParams<T> Small() {
    lbcrypto::CCParams<T> params;

    params.SetPlaintextModulus(1 << 8);
    params.SetRingDim(1 << 12);

    params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);
    params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);

    // Hybrid should be default
    params.SetKeySwitchTechnique(lbcrypto::HYBRID);
    params.SetNumLargeDigits(1);  // |P| ~= |Q|

    // Debugging
    // params.SetFirstModSize(60);
    // params.SetScalingModSize(55);
    // params.SetStandardDeviation(.0f);
    // params.SetSecretKeyDist(lbcrypto::SecretKeyDist::UNIFORM_TERNARY);

    // From lattice estimator
    // double sigma = std::pow(2.0, -50);
    // params.SetStandardDeviation(sigma);

    return params;
}
}  // namespace spar::params