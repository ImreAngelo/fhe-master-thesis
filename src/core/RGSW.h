#pragma once

#include "lattice/lat-hal.h"
#include "math/distrgen.h"
#include "math/ternaryuniformgenerator.h"
#include "math/nbtheory.h"
#include "rlwe-ciphertext.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <memory>
#include <vector>

namespace core {

using NativePoly    = lbcrypto::NativePoly;
using NativeInteger = lbcrypto::NativeInteger;
// RLWECt by value (not shared_ptr) for simplicity
using RLWECt = lbcrypto::RLWECiphertextImpl;

// Lightweight parameter bag for single-modulus RGSW/RLWE.
// Does NOT require a BINFHE_METHOD or LWE parameters.
struct RGSWParams {
    uint32_t N;      // ring dimension (must be power of 2)
    NativeInteger Q; // ciphertext modulus (prime, Q ≡ 1 mod 2N for NTT)
    uint32_t baseB;  // gadget base B (power of 2)
    uint32_t digitsG; // ℓ = ceil(log_B(Q)); number of gadget levels

    // Ring Z[X]/(X^N+1) mod Q.  Cyclotomic order passed to ILNativeParams is 2*N.
    std::shared_ptr<lbcrypto::ILNativeParams> polyParams;

    // Gpower[j] = B^j mod Q,  j = 0 .. digitsG-1
    std::vector<NativeInteger> Gpower;

    // Factory: construct and precompute everything from (N, Q, baseB).
    // Q must satisfy Q ≡ 1 (mod 2N) so that NTT exists.
    // Tip: use lbcrypto::LastPrime<NativeInteger>(bits, 2*N) to get such a Q.
    static RGSWParams Make(uint32_t N, NativeInteger Q, uint32_t baseB);
};

// RGSW ciphertext: 2ℓ × 2 matrix of NativePoly stored in EVALUATION format.
//
// Layout (interleaved, matching OpenFHE binfhe convention):
//   rows[2j]   = (a, b):  b = a*sk + e,        a was also given  +μ·Gpower[j]
//   rows[2j+1] = (a, b):  b = a*sk + e + μ·Gpower[j],  a is plain random
//
// External product C ⊡ d = G⁻¹(d) · C decrypts to ≈ μ · plaintext(d).
struct RGSWCt {
    // rows[i][0] = a component,  rows[i][1] = b component  (both EVALUATION)
    std::vector<std::array<NativePoly, 2>> rows;

    RGSWCt() = default;
    RGSWCt(uint32_t digitsG, const std::shared_ptr<lbcrypto::ILNativeParams>& pp);
};

// ---- Key generation ----------------------------------------------------------

// Returns a ternary secret key polynomial in COEFFICIENT format.
NativePoly RGSWKeyGen(const RGSWParams& p);

// ---- RLWE -------------------------------------------------------------------

// Encrypt mu (COEFFICIENT format, arbitrary polynomial) under sk (COEFFICIENT).
// scaling is the plaintext-to-ciphertext scaling factor (e.g., Q/2 for 1-bit messages).
// Returns ciphertext in EVALUATION format.
RLWECt RLWEEncrypt(const RGSWParams& p, const NativePoly& sk, const NativePoly& mu,
                   NativeInteger scaling);

// Decrypt ct under sk (COEFFICIENT).
// Returns b − a·sk in COEFFICIENT format (≈ mu·scaling + small noise).
NativePoly RLWEDecrypt(const RGSWParams& p, const NativePoly& sk, const RLWECt& ct);

// ---- RGSW -------------------------------------------------------------------

// Encrypt mu (COEFFICIENT format, small/binary coefficients) as C = Z + μ·G.
// Returns a 2ℓ×2 matrix in EVALUATION format.
RGSWCt RGSWEncrypt(const RGSWParams& p, const NativePoly& sk, const NativePoly& mu);

// ---- External product & CMux ------------------------------------------------

// Gadget decomposition: G⁻¹(d) → 2ℓ polynomials in COEFFICIENT format.
//   output[2j]   = j-th base-B digit of d.GetElements()[0]
//   output[2j+1] = j-th base-B digit of d.GetElements()[1]
// Uses the full ℓ digits (unlike OpenFHE binfhe which drops the LSB digit).
std::vector<NativePoly> GadgetDecompose(const RGSWParams& p, const RLWECt& d);

// External product: C ⊡ d = G⁻¹(d) · C.  Result is in EVALUATION format.
RLWECt ExternalProduct(const RGSWParams& p, const RGSWCt& C, const RLWECt& d);

// CMux gate: CMux(C, d1, d0) = C ⊡ (d1 − d0) + d0.
// Selector μ=1 → output ≈ d1;  μ=0 → output ≈ d0.
RLWECt CMux(const RGSWParams& p, const RGSWCt& C, const RLWECt& d1, const RLWECt& d0);

} // namespace core
