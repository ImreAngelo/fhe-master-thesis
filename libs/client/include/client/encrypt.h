#pragma once

#include "core/context.h"
#include "core/types.h"
#include <stdexcept>

namespace spar::client {

using core::ExtendedContext;
using core::RGSW;
using core::RLWE;

inline RLWE Encrypt(const ExtendedContext& cc, const std::vector<RLWE>& cts, const uint32_t n) {
    throw std::logic_error("Not implemented");
};

inline std::vector<RLWE> Decrypt() {
    throw std::logic_error("Not implemented");
};

/// @brief Encrypts a one-hot indicator of length `len` with the 1 at position `idx`
template <typename T>
std::vector<T> EncryptOneHot(const ExtendedContext& cc, const core::PublicKey& pk, const uint32_t len, const uint32_t idx) {
    const auto zero_pt = cc->MakeCoefPackedPlaintext({0});
    const auto one_pt = cc->MakeCoefPackedPlaintext({1});

    std::vector<T> slots(len);
    for (uint32_t i = 0; i < len; i++) {
        const auto& pt = (i == idx) ? one_pt : zero_pt;
        if constexpr (std::is_same_v<T, RLWE>) {
            slots[i] = cc->Encrypt(pk, pt);
        } else {
            static_assert(std::is_same_v<T, RGSW>, "unsupported slot type");
            slots[i] = cc->EncryptRGSW(pk, pt);
        }
    }
    return slots;
}

}  // namespace spar::client