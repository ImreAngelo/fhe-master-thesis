#pragma once
#include "constants-defs.h"
#include "lattice/stdlatticeparms.h"
#include "openfhe.h"

#include <optional>
#include <stdexcept>

// TODO: Make parameters shared with benchmarks and match benchmark values with unit tests
namespace spar::params {

/// @brief Named parameter sets for the factory
enum class Set {
    Standard,     ///< Large parameters, supports SIMD (N = 2^14, Q = 180 bits)
    Small,        ///< sPAR paper parameters (N = 2^12, Q = 64 bits)
    SmallHybrid,  ///< Small with HYBRID key switching (N = 2^13)
};

namespace {

/// @brief Parameter values for one set; std::nullopt keeps OpenFHE's default
struct Values {
    std::optional<PlaintextModulus> plaintextModulus;
    std::optional<uint32_t> ringDim;
    std::optional<lbcrypto::SecurityLevel> securityLevel;
    std::optional<lbcrypto::ScalingTechnique> scalingTechnique;
    std::optional<uint32_t> multiplicativeDepth;  ///< k = depth + 1
    std::optional<uint32_t> firstModSize;
    std::optional<uint32_t> scalingModSize;
    std::optional<float> standardDeviation;
    std::optional<lbcrypto::KeySwitchTechnique> keySwitchTechnique;
    std::optional<uint32_t> numLargeDigits;
};

inline constexpr Values kStandard{
    /*plaintextModulus*/ 65537,
    /*ringDim*/ 1u << 14,
    /*securityLevel*/ lbcrypto::SecurityLevel::HEStd_NotSet,
    /*scalingTechnique*/ lbcrypto::FIXEDMANUAL,
    /*multiplicativeDepth*/ 4,
    /*firstModSize*/ 60,
    /*scalingModSize*/ 59,
    /*standardDeviation*/ 3.19,
    /*keySwitchTechnique*/ lbcrypto::HYBRID,  // For GHS
    /*numLargeDigits*/ 1,
};

inline constexpr Values kSmall{
    /*plaintextModulus*/ 1u << 8,
    /*ringDim*/ 1u << 12,
    /*securityLevel*/ lbcrypto::SecurityLevel::HEStd_NotSet,
    /*scalingTechnique*/ lbcrypto::FIXEDMANUAL,
    /*multiplicativeDepth*/ 2,
    /*firstModSize*/ 24,
    /*scalingModSize*/ 20,
    /*standardDeviation*/ 512,
    /*keySwitchTechnique*/ std::nullopt,
    /*numLargeDigits*/ std::nullopt,
};

inline constexpr Values kSmallHybrid{
    /*plaintextModulus*/ 1u << 8,
    /*ringDim*/ 1u << 13,  // Larger ring for hybrid to support larger QP modulus
    /*securityLevel*/ lbcrypto::SecurityLevel::HEStd_NotSet,
    /*scalingTechnique*/ lbcrypto::FIXEDMANUAL,
    /*multiplicativeDepth*/ 2,
    /*firstModSize*/ 24,
    /*scalingModSize*/ 20,
    /*standardDeviation*/ 512,
    /*keySwitchTechnique*/ lbcrypto::HYBRID,
    /*numLargeDigits*/ 1,  // |P| ~= |Q|
};

inline constexpr const Values& Get(const Set set) {
    switch(set) {
        case Set::Standard: return kStandard;
        case Set::Small: return kSmall;
        case Set::SmallHybrid: return kSmallHybrid;
    }
    throw std::invalid_argument("Unknown parameter set");
}

}  // namespace

/// @brief Factory for constructing a parameter set by name
template <typename T = lbcrypto::CryptoContextBGVRNS>
inline lbcrypto::CCParams<T> Make(const Set set) {
    using Params = lbcrypto::CCParams<T>;
    const Values& values = Get(set);

    Params params;
    const auto apply = [&params](auto setter, const auto& value) {
        if(value) (params.*setter)(*value);
    };

    apply(&Params::SetPlaintextModulus, values.plaintextModulus);
    apply(&Params::SetRingDim, values.ringDim);
    apply(&Params::SetSecurityLevel, values.securityLevel);
    apply(&Params::SetScalingTechnique, values.scalingTechnique);
    apply(&Params::SetMultiplicativeDepth, values.multiplicativeDepth);
    apply(&Params::SetFirstModSize, values.firstModSize);
    apply(&Params::SetScalingModSize, values.scalingModSize);
    apply(&Params::SetStandardDeviation, values.standardDeviation);
    apply(&Params::SetKeySwitchTechnique, values.keySwitchTechnique);
    apply(&Params::SetNumLargeDigits, values.numLargeDigits);

    return params;
}

}  // namespace spar::params
