#pragma once
#include "openfhe.h"

/**
 * @brief RGSW ciphertext stored using the hybrid-keyswitch RNS digit gadget.
 *
 * Each side (top, bot) holds dnum (a, b) pairs in QP basis (extended CRT basis
 * of the underlying BGV-RNS context). These pairs satisfy:
 *
 *   topB[j] + topA[j] * s  ≈  m * P * g_j * s   (mod QP)
 *   botB[j] + botA[j] * s  ≈  m * P * g_j       (mod QP)
 *
 * where g_j is the QP element holding [P]_{q_i} in tower i ∈ partition j and
 * 0 elsewhere, and s is the BGV secret extended to QP. The external product
 * reuses OpenFHE's KeySwitchHYBRID::EvalKeySwitchPrecomputeCore (one ModUp on
 * each RLWE component) followed by EvalFastKeySwitchCore (inner product +
 * ApproxModDown back to Q). The number of (a, b) pairs equals the context's
 * `dnum = numPartQ`, set via CCParams<CryptoContextBGVRNS>::SetNumLargeDigits.
 */
template <typename T>
struct RGSWCiphertext {
    std::vector<T> topA, topB;
    std::vector<T> botA, botB;

    size_t size() const { return topA.size(); }
};
