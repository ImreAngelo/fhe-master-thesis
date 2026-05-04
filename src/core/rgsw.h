#pragma once
#include "openfhe.h"
#include "key/evalkeyrelin.h"

/**
 * @brief RGSW ciphertext stored using the hybrid-keyswitch RNS digit gadget.
 *
 * Each side (top, bot) is an `EvalKey<DCRTPoly>` holding `dnum` (a, b) pairs in
 * QP basis (extended CRT basis of the underlying BGV-RNS context):
 *
 *   top.B[j] + top.A[j] * s  ≈  m * P * g_j * s   (mod QP)
 *   bot.B[j] + bot.A[j] * s  ≈  m * P * g_j       (mod QP)
 *
 * where g_j is the QP element holding [P]_{q_i} in tower i ∈ partition j and 0
 * elsewhere, and s is the BGV secret extended to QP. Storing the rows as
 * `EvalKey` lets the external/internal product call OpenFHE's
 * `KeySwitchHYBRID::EvalFastKeySwitchCoreExt` directly — same primitive that
 * relinearization uses. Number of (a, b) pairs equals the context's
 * `dnum = numPartQ`, set via `CCParams<CryptoContextBGVRNS>::SetNumLargeDigits`.
 */
template <typename T>
struct RGSWCiphertext {
    lbcrypto::EvalKey<T> top;
    lbcrypto::EvalKey<T> bot;

    size_t size() const { return top ? top->GetAVector().size() : 0; }
};
