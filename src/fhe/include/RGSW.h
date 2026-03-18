#pragma once
#include "openfhe.h"
#include "key/privatekey.h"
#include "schemerns/rns-cryptoparameters.h"

namespace fhe {

using namespace lbcrypto;

/**
 * RGSW ciphertext of a ring element m under secret key s.
 *
 * An RGSW ciphertext consists of two rows of l RLWE ciphertexts,
 * stored as parallel A/B vectors (matching OpenFHE's EvalKeyRelinImpl layout):
 *
 *   Row 0  { (b0[i], a0[i]) }: RLWE(m · g_i)     — for c_0 decomposition
 *   Row 1  { (b1[i], a1[i]) }: RLWE(m·s · g_i)   — for c_1 decomposition
 *
 * where g_i are the BV-style CRT gadget elements (one per CRT limb when
 * digitSize == 0, or one per digit-within-limb when digitSize > 0).
 *
 * Both rows are needed so that the external product can decompose BOTH
 * components (c_0, c_1) of the input RLWE ciphertext and correctly
 * reconstruct RLWE(m·v):
 *
 *   result_b + result_a·s
 *       ≈  Σ_i d0_i·(m·g_i) + Σ_i d1_i·(m·s·g_i)
 *       =  m · (Σ_i d0_i·g_i  +  s · Σ_i d1_i·g_i)
 *       ≈  m · (c_0 + s·c_1)
 *       =  m · v
 */
struct RGSWCiphertext {
    std::vector<DCRTPoly> b0, a0;  // Row 0: RLWE(m · g_i)
    std::vector<DCRTPoly> b1, a1;  // Row 1: RLWE(m·s · g_i)
    uint32_t digitSize{0};         // 0 = one digit per CRT limb (BV default)
};

/**
 * Converts an RLWE ciphertext ct = RLWE_s(m) into an RGSW ciphertext RGSW_s(m).
 *
 * Requires the secret key because row 1 encrypts m·s·g_i: without s we cannot
 * form the message polynomial m·s needed for that row.
 *
 * The RGSW is generated at the same CRT level as the input ciphertext.
 * Use EvalExternalProduct only with ciphertexts at the same level.
 *
 * Noise model: mPoly = c_0 + c_1·s ≈ m + e  (small error e from RLWE).
 * The row-1 message msPoly = mPoly·s introduces error e·s, which is small
 * for binary/ternary secret keys (the standard in BFV/BGV).
 */
RGSWCiphertext HomExpand(const CryptoContext<DCRTPoly>& cc,
                         const Ciphertext<DCRTPoly>&    ct,
                         const PrivateKey<DCRTPoly>&    sk);

/**
 * Computes the RGSW external product:  RGSW(m) ⊡ RLWE(v)  →  RLWE(m·v).
 *
 * Algorithm (BV-style, matches EvalFastKeySwitchCore):
 *   digits0 = CRTDecompose(c_0),  digits1 = CRTDecompose(c_1)
 *   result_b = Σ_i  digits0[i]·b0[i]  +  digits1[i]·b1[i]
 *   result_a = Σ_i  digits0[i]·a0[i]  +  digits1[i]·a1[i]
 *
 * The rgsw must have been generated from a ciphertext at the same CRT level
 * as ct (i.e. same number of active CRT limbs).
 */
Ciphertext<DCRTPoly> EvalExternalProduct(const CryptoContext<DCRTPoly>& cc,
                                         const RGSWCiphertext&          rgsw,
                                         const Ciphertext<DCRTPoly>&    ct);

} // namespace fhe
