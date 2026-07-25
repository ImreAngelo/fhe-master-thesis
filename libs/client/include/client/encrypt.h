#pragma once

#include "core/context.h"
#include "core/types.h"
#include <stdexcept>

namespace spar::client {

inline core::RLWE Encrypt(const core::ExtendedContext& cc, const std::vector<core::RLWE>& cts, const uint32_t n) {
    throw std::logic_error("Not implemented");
};

/// @brief Partially decrypt array
std::vector<core::RLWE> Decrypt(const core::CryptoContext&, const std::vector<core::RLWE>& cts, const core::PrivateKey&,
                                const bool is_lead = false);

/// @brief Encrypts a one-hot indicator of length `len` with the 1 at position `idx`
template <typename T>
inline std::vector<T> EncryptOneHot(const core::ExtendedContext& cc, const core::PublicKey& pk, const uint32_t len, const uint32_t idx) {
    const auto zero_pt = cc->MakeCoefPackedPlaintext({0});
    const auto one_pt = cc->MakeCoefPackedPlaintext({1});

    std::vector<T> slots(len);
    for (uint32_t i = 0; i < len; i++) {
        const auto& pt = (i == idx) ? one_pt : zero_pt;
        if constexpr (std::is_same_v<T, core::RLWE>) {
            slots[i] = cc->Encrypt(pk, pt);
        } else {
            static_assert(std::is_same_v<T, core::RGSW>, "unsupported slot type");
            slots[i] = cc->EncryptRGSW(pk, pt);
        }
    }
    return slots;
}

}  // namespace spar::client