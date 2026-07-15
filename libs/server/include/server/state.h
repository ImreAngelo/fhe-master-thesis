#pragma once

#include "core/context.h"
#include "core/types.h"
#include "server/types.h"

namespace spar::server {

/// @brief Returns a new
template <uint32_t K = 3>
std::pair<Matrix<RGSW, K>, Matrix<RLWE, K>> InitializeState(const core::ExtendedContext& cc, const core::PublicKey& pk, const uint32_t n) {
    const auto zero = cc->Encrypt(pk, cc->MakeCoefPackedPlaintext({0})); // TODO: Make noiseless
    const auto one = cc->MakePublicRGSW(pk, cc->MakeCoefPackedPlaintext({1}));

    // I = "slot available" indicator: starts at 1, decremented when slot is taken.
    // L = value accumulator at slot: starts at 0, written values added in.
    Matrix<RGSW, K> I(n);
    Matrix<RLWE, K> L(n);

    for (uint32_t i = 0; i < n; i++) {
        for (uint32_t k = 0; k < K; k++) {
            L[i][k] = zero;
            I[i][k] = one;
        }
    }

    return {I, L};
}

}  // namespace spar::server