#pragma once

#include "core/context.h"
#include "types.h"

namespace spar::server {

// Not full write

/// @brief Second loop of algorithm 2
///
/// @param cc Extended crypto context
/// @param pk Public key
/// @param Vr Value encrypted under another scheme
/// @param n Number of users
/// @param L Server-state of written values
/// @param I Server-state of available slots
/// @param z Encrypted index bits
/// @param debug_sk Secret key used only for noise instrumentation (optional)
///
/// @return
template <uint32_t K = 3, uint32_t D = 3>
core::RGSW Write(const core::ExtendedContext& cc, const core::PublicKey& pk, const core::Plaintext& Vr, const uint32_t n, Matrix<K>& L,
                 Matrix<K>& I, const std::vector<std::vector<core::RGSW>>& z,
                 // Debugging
                 const core::PrivateKey& debug_sk = nullptr);

}  // namespace spar::server