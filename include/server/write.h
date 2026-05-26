#pragma once

#include "../scheme/context.h"
#include "../scheme/types.h"
#include "openfhe.h"

namespace spar::server {

/// @brief Second loop of algorithm 2
/// 
/// @param cc Extended crypto context
/// @param pk Public key
/// @param Vr Value encrypted under another scheme
/// @param n Number of users
/// @param L Server-state of written values
/// @param I Server-state of available slots
/// @param z Encrypted index bits
///
/// @return 
template<uint32_t K = 3, uint32_t D = 3>
RGSW Write(
    const ExtendedContext& cc, 
    const PublicKey& pk,
    const Plaintext& Vr,
    const uint32_t n,
    ServerMatrix<RGSW, K>& L,
    ServerMatrix<RGSW, K>& I,
    const std::vector<std::vector<RGSW>>& z
    // Debugging
    // const PrivateKey& debug_sk
);

} // namespace spar::server