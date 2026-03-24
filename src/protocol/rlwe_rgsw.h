/**
 * rlwe_rgsw.hpp
 *
 * RLWE → RGSW homomorphic expansion using OpenFHE native polynomial types.
 *
 * Implements:
 *   Server::KeySwitch       — RLWE key switching  (Alg. 7, Onion Ring appendix)
 *   Server::Subs            — Substitution X→X^k  (Alg. 8, Onion Ring appendix)
 *   Server::ExpandRlwe      — Bit extraction       (Alg. 3, Onion Ring)
 *   Server::ExternalProduct — RGSW ⊡ RLWE → RLWE  (standard TFHE primitive)
 *   Server::HomExpand       — Full expansion       (Alg. 4, Onion Ring ≡ RLWEtoRGSW, Sorting Hat)
 *   Client::SampleSecretKey
 *   Client::PackBits        — Pack n bits into ell scaled RLWE ciphertexts
 *   Client::Setup           — Generate all evaluation keys
 *   Client::Decrypt         — Decrypt a single RLWE ciphertext (verification only)
 *
 * Security boundary:
 *   Client:: has access to `secretKey` (a RingElem).
 *   Server:: receives only EvalKey (public eval material) and packed ciphertexts.
 *   Nothing inside Server:: touches the secret key.
 *
 * References:
 *   [OnionRing]  Asharov et al., "Onion Ring ORAM", CCS 2020
 *   [SortingHat] Cong et al., "Sorting Hat", CCS 2022
 *
 * Build:  see CMakeLists.txt
 *
 * Parameter guidance (production):
 *   n = 2048, q = 2^27−1 (NTT prime ≡ 1 mod 2n), ell=4, logB=7, ellKs=4, logBks=7, sigma=3.19
 *   Toy demo uses n=32, q=786433 (NTT prime: 786433=3·2^18+1, works for n≤2^17).
 */

#pragma once

#include <cstdint>
#include <vector>
#include <cassert>
#include <memory>
#include <stdexcept>
#include <algorithm>

// ── OpenFHE headers ───────────────────────────────────────────────────────────
// Adjust include paths to match your OpenFHE installation.
#include "math/hal/nativeintbackend.h"
#include "math/discretegaussiangenerator.h"
#include "math/discreteuniformgenerator.h"
#include "lattice/lat-hal.h"

using namespace lbcrypto;

// ══════════════════════════════════════════════════════════════════════════════
// §1  BASE TYPES
// ══════════════════════════════════════════════════════════════════════════════

/// A polynomial in Z_q[X]/(X^n+1).
using RingElem = NativePoly;

// ─── Cryptographic parameters ────────────────────────────────────────────────
struct Params {
    /// OpenFHE ring descriptor; cyclotomic order = 2n.
    std::shared_ptr<ILNativeParams> ring;

    NativeInteger q;      ///< Ciphertext modulus (NTT-friendly prime, q ≡ 1 mod 2n).
    uint32_t      n;      ///< Ring dimension (power of 2).
    uint32_t      ell;    ///< RGSW gadget length  (ell ≈ log_B(q)).
    uint32_t      logB;   ///< log₂ of RGSW gadget base B.
    uint32_t      ellKs;  ///< Key-switching gadget length.
    uint32_t      logBks; ///< log₂ of key-switching gadget base B_ks.
    double        sigma;  ///< Gaussian noise standard deviation.

    uint64_t B()    const noexcept { return UINT64_C(1) << logB;   }
    uint64_t Bks()  const noexcept { return UINT64_C(1) << logBks; }
    uint32_t logN() const noexcept {
        uint32_t k = 0, m = n; while (m >>= 1) ++k; return k;
    }

    /// Factory: construct params and initialise the OpenFHE ring context.
    static Params Make(uint32_t n_, NativeInteger q_,
                       uint32_t ell_, uint32_t logB_,
                       uint32_t ellKs_, uint32_t logBks_,
                       double   sigma_ = 3.19)
    {
        Params p;
        p.n      = n_;
        p.q      = q_;
        p.ell    = ell_;
        p.logB   = logB_;
        p.ellKs  = ellKs_;
        p.logBks = logBks_;
        p.sigma  = sigma_;
        // Cyclotomic order for X^n+1 is 2n.
        p.ring   = std::make_shared<ILNativeParams>(2 * n_, q_);
        return p;
    }
};

// ─── RLWE ciphertext  (a, b)  with  b = a·s + msg + err ─────────────────────
struct RLWECt {
    RingElem a, b;   ///< Both kept in EVALUATION (NTT) format.

    RLWECt() = default;
    RLWECt(RingElem _a, RingElem _b) : a(std::move(_a)), b(std::move(_b)) {}

    RLWECt operator+(const RLWECt& o) const { return {a + o.a, b + o.b}; }
    RLWECt operator-(const RLWECt& o) const { return {a - o.a, b - o.b}; }
};

// ─── RGSW ciphertext: 2·ell RLWE rows ───────────────────────────────────────
//   Row k        (0 ≤ k < ell):  RLWE( m·(−s)/B^(k+1) )   [top half]
//   Row k + ell  (0 ≤ k < ell):  RLWE( m/B^(k+1) )         [bottom half]
//
//   Equivalently: C = Z + m·G  where G = I₂ ⊗ g, g = (1/B, …, 1/B^ell)ᵀ.
using RGSWCt = std::vector<RLWECt>;   // length = 2·ell

// ─── Public evaluation keys (sent from Client to Server) ─────────────────────
struct EvalKey {
    /// substKS[lev][j] = RLWE_s( s(X^{k_lev}) / Bks^(j+1) ),
    ///   where k_lev = n/2^lev + 1 is the automorphism exponent at level lev.
    ///   Dimensions: [logN][ellKs].
    std::vector<std::vector<RLWECt>> substKS;

    /// RGSW encryption of the negated secret key (−s).
    /// Used in Phase 2 of HomExpand to build the top-half rows.
    RGSWCt rgswNegS;
};

// ══════════════════════════════════════════════════════════════════════════════
// §2  POLYNOMIAL UTILITIES  (internal helpers, not part of either namespace)
// ══════════════════════════════════════════════════════════════════════════════

namespace poly {

/// Zero polynomial in EVALUATION format.
inline RingElem Zero(const Params& p) {
    return RingElem(p.ring, EVALUATION, /*initToZero=*/true);
}

/// Uniformly random polynomial in EVALUATION format.
inline RingElem UniformRandom(const Params& p) {
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(p.q);
    return RingElem(dug, p.ring, EVALUATION);
}

/// Small-coefficient Gaussian error polynomial.
inline RingElem GaussianError(const Params& p) {
    DiscreteGaussianGeneratorImpl<NativeVector> dgg(p.sigma);
    RingElem e(dgg, p.ring, COEFFICIENT);
    e.SetFormat(EVALUATION);
    return e;
}

/// Right-shift all (centered) coefficients by `bits`: implements division by 2^bits.
/// Used to scale a message m → m/B^k = m >> (k·logB).
inline RingElem RightShift(RingElem poly, uint32_t bits, const Params& p) {
    poly.SetFormat(COEFFICIENT);
    NativeVector v       = poly.GetValues();
    uint64_t     qVal    = p.q.ConvertToInt<uint64_t>();
    uint64_t     qHalf   = (qVal + 1) >> 1;

    for (uint32_t i = 0; i < p.n; i++) {
        uint64_t c = v[i].ConvertToInt<uint64_t>();
        // Centre: treat [qHalf, q) as the negative interval (−qHalf, 0].
        bool neg = (c >= qHalf);
        if (neg) c = qVal - c;   // absolute value
        c >>= bits;              // divide
        if (neg) c = qVal - c;   // restore sign
        v[i] = NativeInteger(c);
    }
    RingElem r(p.ring, COEFFICIENT, false);
    r.SetValues(v, COEFFICIENT);
    r.SetFormat(EVALUATION);
    return r;
}

/// Build the monomial X^{-k} in Z_q[X]/(X^n+1) as a ring element.
///
/// Identity: X^{-k} = X^{2n−k} mod (X^n+1).
///   If 2n−k < n : coefficient +1 at position (2n−k).
///   If 2n−k ≥ n : X^{2n−k} = X^n · X^{n−k} = (−1)·X^{n−k},
///                  so coefficient −1 at position (2n−k−n) = (n−k).
inline RingElem XNegK(uint32_t k, const Params& p) {
    k = k % (2 * p.n);                        // reduce to [0, 2n)
    uint32_t     exp  = (2 * p.n - k) % (2 * p.n);
    NativeVector v(p.n, p.q);
    for (uint32_t i = 0; i < p.n; i++) v[i] = NativeInteger(0);

    if (exp < p.n) {
        v[exp] = NativeInteger(1);
    } else {
        v[exp - p.n] = p.q - NativeInteger(1);   // −1 mod q
    }
    RingElem r(p.ring, COEFFICIENT, false);
    r.SetValues(v, COEFFICIENT);
    r.SetFormat(EVALUATION);
    return r;
}

/// Signed balanced gadget decomposition of `poly` in base 2^logBase.
/// Returns `ellLen` polynomials d[0], …, d[ellLen−1] with coefficients in
/// (−B/2, B/2] such that poly ≈ Σ_j d[j]·B^(j+1) (with small carry error).
inline std::vector<RingElem> GadgetDecompose(
    RingElem poly, uint32_t logBase, uint32_t ellLen, const Params& p)
{
    poly.SetFormat(COEFFICIENT);
    const uint64_t B     = UINT64_C(1) << logBase;
    const uint64_t halfB = B >> 1;
    const uint64_t mask  = B - 1;
    const uint64_t qVal  = p.q.ConvertToInt<uint64_t>();
    const uint64_t qHalf = (qVal + 1) >> 1;

    // Copy coefficients into a signed working array.
    std::vector<int64_t> raw(p.n);
    for (uint32_t i = 0; i < p.n; i++) {
        uint64_t c = poly[i].ConvertToInt<uint64_t>();
        raw[i] = (c >= qHalf) ? (int64_t)c - (int64_t)qVal : (int64_t)c;
    }

    std::vector<RingElem> result;
    result.reserve(ellLen);

    for (uint32_t j = 0; j < ellLen; j++) {
        NativeVector digits(p.n, p.q);
        for (uint32_t i = 0; i < p.n; i++) {
            // Signed digit in [0, B), then centred to (−B/2, B/2].
            int64_t di = raw[i] & (int64_t)mask;
            if ((uint64_t)di > halfB) di -= (int64_t)B;
            raw[i] = (raw[i] - di) >> (int)logBase;    // propagate remainder
            // Reduce digit to Z_q (unsigned representation).
            uint64_t dMod = (di < 0) ? (uint64_t)(di + (int64_t)qVal) : (uint64_t)di;
            digits[i] = NativeInteger(dMod);
        }
        RingElem dj(p.ring, COEFFICIENT, false);
        dj.SetValues(digits, COEFFICIENT);
        dj.SetFormat(EVALUATION);
        result.push_back(std::move(dj));
    }
    return result;
}

}  // namespace poly

// ══════════════════════════════════════════════════════════════════════════════
// §3  CLIENT NAMESPACE  ── has access to the plaintext secret key
// ══════════════════════════════════════════════════════════════════════════════
//
//   The Client's job:
//     1. Generate (or receive) a binary secret key s ∈ {0,1}^n.
//     2. Build EvalKey: substitution key-switch keys + RGSW(−s).
//     3. Pack the plaintext bits into ell scaled RLWE ciphertexts.
//     4. Send (packed ciphertexts, EvalKey) to Server — keep s private.

namespace Client {

/// Sample a binary secret key: coefficients drawn uniformly from {0, 1}.
inline RingElem SampleSecretKey(const Params& p) {
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(NativeInteger(2));            // binary coefficients
    NativeVector binaryVec = dug.GenerateVector(p.n);

    NativeVector lifted(p.n, p.q);
    for (uint32_t i = 0; i < p.n; i++) lifted[i] = binaryVec[i];

    RingElem s(p.ring, COEFFICIENT, false);
    s.SetValues(lifted, COEFFICIENT);
    s.SetFormat(EVALUATION);
    return s;
}

/// Encrypt a ring element `msg` (in EVALUATION format) under secret key `s`.
/// Returns RLWE_s(msg) = (a, b) with b = a·s + msg + e.
inline RLWECt Encrypt(const RingElem& msg, const RingElem& s, const Params& p) {
    RingElem a = poly::UniformRandom(p);
    RingElem e = poly::GaussianError(p);
    RingElem b = a * s + msg + e;
    return {a, b};
}

/// Decrypt RLWE_s(msg): returns b − a·s ≈ msg (mod q).
/// For verification only — never call this on the Server.
inline RingElem Decrypt(const RLWECt& ct, const RingElem& s, const Params& p) {
    return ct.b - ct.a * s;   // ≈ msg + small error
}

/// Generate the ellKs key-switching keys for the substitution X → X^k.
///   substKS[j] = RLWE_s( s(X^k) / Bks^(j+1) ),   j = 0 … ellKs−1.
///
/// Security note: s(X^k) is still determined by s, so these keys reveal
/// no extra information beyond what RLWE security already allows.
inline std::vector<RLWECt> GenSubstKSKeys(
    const RingElem& s, uint32_t substExp, const Params& p)
{
    // Automorphism s(X) → s(X^k): permute coefficients in ring Z_q[X]/(X^n+1).
    // AutomorphismTransform operates in COEFFICIENT domain.
    RingElem s_coeff = s;
    s_coeff.SetFormat(COEFFICIENT);
    RingElem s_at_k = s_coeff.AutomorphismTransform(substExp);
    s_at_k.SetFormat(EVALUATION);

    std::vector<RLWECt> keys;
    keys.reserve(p.ellKs);
    for (uint32_t j = 0; j < p.ellKs; j++) {
        // Message: s(X^k) / Bks^(j+1)  — scale down by right-shifting (j+1)·logBks bits.
        RingElem msg = poly::RightShift(s_at_k, (j + 1) * p.logBks, p);
        keys.push_back(Encrypt(msg, s, p));
    }
    return keys;
}

/// Generate all logN substitution key-switch key sets (one per expansion level).
/// Level lev uses automorphism exponent  k_lev = n/2^lev + 1.
inline std::vector<std::vector<RLWECt>> GenAllSubstKSKeys(
    const RingElem& s, const Params& p)
{
    uint32_t logN = p.logN();
    std::vector<std::vector<RLWECt>> all(logN);
    for (uint32_t lev = 0; lev < logN; lev++) {
        uint32_t k = p.n / (1u << lev) + 1;     // always odd (since n is even, n/2^lev ≥ 2)
        all[lev]   = GenSubstKSKeys(s, k, p);
    }
    return all;
}

/// Generate RGSW(−s): a 2·ell × 2 matrix encrypting the negated secret.
///
/// Mathematical structure:
///   Row k        = RLWE( s²/B^(k+1) )     [top half: (−s)·(−s)/B^(k+1)]
///   Row k + ell  = RLWE( (−s)/B^(k+1) )   [bottom half]
///
/// This is the auxiliary key A used in Phase 2 of HomExpand.
inline RGSWCt GenRGSWNegS(const RingElem& s, const Params& p) {
    RingElem neg_s = poly::Zero(p) - s;    // −s mod q

    // s² = s·s  (used for top half: (−s)·(−s) = s²)
    RingElem s_sq = s * s;

    RGSWCt ct(2 * p.ell);
    for (uint32_t k = 0; k < p.ell; k++) {
        uint32_t shift = (k + 1) * p.logB;

        // Top half row k:   RLWE( s² / B^(k+1) )
        ct[k]        = Encrypt(poly::RightShift(s_sq,  shift, p), s, p);

        // Bottom half row k: RLWE( (−s) / B^(k+1) )
        ct[k + p.ell] = Encrypt(poly::RightShift(neg_s, shift, p), s, p);
    }
    return ct;
}

/// Build all evaluation keys and bundle them for Server consumption.
inline EvalKey Setup(const RingElem& s, const Params& p) {
    EvalKey ek;
    ek.substKS  = GenAllSubstKSKeys(s, p);
    ek.rgswNegS = GenRGSWNegS(s, p);
    return ek;
}

/// Pack n plaintext bits into ell RLWE ciphertexts, one per gadget level.
///
/// Input format: bits[i] ∈ {0, 1}, length = n.
///
/// For each level k = 0 … ell−1, produces:
///   packed[k] = RLWE_s( Σᵢ bits[i]·Xⁱ / (n·B^(k+1)) )
///
/// The factor 1/(n·B^(k+1)) = 1/n · 1/B^(k+1) is applied via integer right-shifts:
///   total shift = logN + (k+1)·logB.
///
/// After Server::ExpandRlwe, the 1/n factor is cancelled by the n-fold noise
/// amplification of the log-n-deep splitting tree, leaving RLWE(bits[i]/B^(k+1)).
inline std::vector<RLWECt> PackBits(
    const std::vector<uint32_t>& bits,
    const RingElem&              s,
    const Params&                p)
{
    if (bits.size() != p.n)
        throw std::invalid_argument("PackBits: bits.size() must equal n");

    // m = Σᵢ bits[i]·Xⁱ  (coefficient polynomial)
    NativeVector coeffs(p.n, p.q);
    for (uint32_t i = 0; i < p.n; i++) coeffs[i] = NativeInteger(bits[i] & 1u);
    RingElem m(p.ring, COEFFICIENT, false);
    m.SetValues(coeffs, COEFFICIENT);
    m.SetFormat(EVALUATION);

    uint32_t logN = p.logN();
    std::vector<RLWECt> packed;
    packed.reserve(p.ell);
    for (uint32_t k = 0; k < p.ell; k++) {
        uint32_t shift = logN + (k + 1) * p.logB;
        packed.push_back(Encrypt(poly::RightShift(m, shift, p), s, p));
    }
    return packed;
}

}  // namespace Client

// ══════════════════════════════════════════════════════════════════════════════
// §4  SERVER NAMESPACE  ── no access to the plaintext secret key
// ══════════════════════════════════════════════════════════════════════════════
//
//   The Server's job:
//     Phase 1 (ExpandRlwe): use substitution + key-switching to unpack n
//              individual RLWE ciphertexts from each packed ciphertext.
//     Phase 2 (HomExpand):  for each bit position, assemble the 2ell×2
//              RGSW matrix by combining Phase-1 outputs with ExternalProduct.

namespace Server {

/// RLWE key switching: transform RLWE_{s'}(μ) → RLWE_s(μ) (Algorithm 7, Onion Ring).
///
/// ks_keys[j] = RLWE_s( s' / Bks^(j+1) )
///
/// Algorithm:
///   1. Decompose c.a = Σ_j d[j]/Bks^(j+1) + tiny error.
///   2. result = (0, c.b) − Σ_j d[j] · ks_keys[j].
///
/// Correctness: (0, c.b) − Σ d[j]·ks_keys[j]  decrypts under s to
///   c.b − a·s = a'·s' + μ + err_orig − (s'·a' − tiny) ≈ μ + small noise.
inline RLWECt KeySwitch(
    const RLWECt&              c,
    const std::vector<RLWECt>& ks_keys,
    const Params&              p)
{
    if (ks_keys.size() != p.ellKs)
        throw std::invalid_argument("KeySwitch: wrong number of KS keys");

    auto digits = poly::GadgetDecompose(c.a, p.logBks, p.ellKs, p);

    // Start with (0, c.b) and subtract digit[j] · key[j] for each level.
    RLWECt result(poly::Zero(p), c.b);
    for (uint32_t j = 0; j < p.ellKs; j++) {
        result.a = result.a - digits[j] * ks_keys[j].a;
        result.b = result.b - digits[j] * ks_keys[j].b;
    }
    return result;
}

/// Polynomial substitution X → X^k (Algorithm 8, Onion Ring).
///
/// Applies the ring automorphism φ_k : f(X) ↦ f(X^k) to both components of c,
/// then key-switches back from secret s(X^k) to the original secret s(X).
///
/// subs_ks[j] = RLWE_s( s(X^k)/Bks^(j+1) )  [pre-computed by Client]
inline RLWECt Subs(
    const RLWECt&              c,
    uint32_t                   k,
    const std::vector<RLWECt>& subs_ks,
    const Params&              p)
{
    // AutomorphismTransform requires COEFFICIENT format.
    RingElem a_coeff = c.a; a_coeff.SetFormat(COEFFICIENT);
    RingElem b_coeff = c.b; b_coeff.SetFormat(COEFFICIENT);

    RingElem a_k = a_coeff.AutomorphismTransform(k);
    RingElem b_k = b_coeff.AutomorphismTransform(k);

    a_k.SetFormat(EVALUATION);
    b_k.SetFormat(EVALUATION);

    // c' = (a(X^k), b(X^k)) now encrypts μ(X^k) under s(X^k).
    // Key-switch from s(X^k) to s(X).
    return KeySwitch({a_k, b_k}, subs_ks, p);
}

/// RLWE coefficient extraction (Algorithm 3, Onion Ring).
///
/// Input:  c = RLWE_s( Σᵢ bᵢ·Xⁱ / (n·B^(k+1)) ),  bᵢ ∈ {0,1}.
/// Output: expanded[i] = RLWE_s( bᵢ/B^(k+1) ),  0 ≤ i < n.
///
/// Method: log(n) rounds of binary splitting using the identity
///   c + Subs(c, n+1)          → RLWE( 2 Σ b_{2i} X^{2i} )  [even coefficients]
///   X^{-1} · (c − Subs(c, n+1)) → RLWE( 2 Σ b_{2i+1} X^{2i} )  [odd coefficients]
/// generalised to X → X^{n/2^lev + 1} at each level.
///
/// In-place processing: at level lev there are 2^lev active ciphertexts in
/// slots 0 … 2^lev−1. Processing in reverse slot order ensures each input slot
/// is read before it is overwritten by its two children.
inline std::vector<RLWECt> ExpandRlwe(
    const RLWECt& c,
    const EvalKey& ek,
    const Params&  p)
{
    uint32_t logN = p.logN();
    std::vector<RLWECt> ciphers(p.n);
    ciphers[0] = c;

    for (uint32_t lev = 0; lev < logN; lev++) {
        // k = n/2^lev + 1  (always odd: n/2^lev is even for lev < logN).
        uint32_t k      = p.n / (1u << lev) + 1;
        uint32_t stride = 1u << lev;     // number of active ciphertexts at this level

        // Process in reverse order: slot `b` writes to {2b, 2b+1}; since 2b ≥ b,
        // reverse traversal guarantees ciphers[b] is not yet overwritten.
        for (int32_t b = (int32_t)stride - 1; b >= 0; --b) {
            RLWECt cur = ciphers[b];     // copy before potential overwrite at b=0
            RLWECt sub = Subs(cur, k, ek.substKS[lev], p);

            // Even branch: cur + Subs(cur, k)
            //   encrypts 2·Σ (message coefficients at even positions w.r.t. this level)
            RLWECt even_ct = cur + sub;

            // Odd branch: (cur − Subs(cur, k)) · X^{-k}
            //   encrypts 2·Σ (message coefficients at odd positions w.r.t. this level)
            RLWECt diff    = cur - sub;
            RingElem xnk   = poly::XNegK(k, p);
            RLWECt odd_ct  = {diff.a * xnk, diff.b * xnk};

            ciphers[2 * b]     = std::move(even_ct);
            ciphers[2 * b + 1] = std::move(odd_ct);
        }
    }
    // After logN rounds, ciphers[i] = RLWE( bᵢ/B^(k+1) ).
    return ciphers;
}

/// RGSW ⊡ RLWE external product (standard TFHE primitive).
///
/// A ⊡ d = G^{-1}(d) · A  ≈  RLWE( m_A · m_d )
///
/// where G^{-1}(d) = [G^{-1}(a_d) | G^{-1}(b_d)] is a 1×2ell row vector of
/// small-coefficient polynomials, and A is the 2ell×2 RGSW matrix.
///
/// Decompose d=(a_d,b_d) into 2ell digits, then accumulate:
///   result = Σ_{k<ell} da[k]·A[k]  +  Σ_{k<ell} db[k]·A[k+ell]
inline RLWECt ExternalProduct(
    const RGSWCt& A,
    const RLWECt& d,
    const Params& p)
{
    if (A.size() != 2 * p.ell)
        throw std::invalid_argument("ExternalProduct: RGSW has wrong number of rows");

    // Gadget-decompose both components of the RLWE ciphertext.
    auto da = poly::GadgetDecompose(d.a, p.logB, p.ell, p);   // ell digits for a_d
    auto db = poly::GadgetDecompose(d.b, p.logB, p.ell, p);   // ell digits for b_d

    RLWECt result(poly::Zero(p), poly::Zero(p));
    for (uint32_t k = 0; k < p.ell; k++) {
        // Contribution from top half A[k]: multiplied by da[k].
        result.a = result.a + da[k] * A[k].a;
        result.b = result.b + da[k] * A[k].b;
        // Contribution from bottom half A[k+ell]: multiplied by db[k].
        result.a = result.a + db[k] * A[k + p.ell].a;
        result.b = result.b + db[k] * A[k + p.ell].b;
    }
    return result;
}

/// Full RLWE → RGSW homomorphic expansion (Algorithm 4, Onion Ring / RLWEtoRGSW, Sorting Hat).
///
/// Input:
///   packed[k] = RLWE( Σᵢ bᵢ·Xⁱ / (n·B^(k+1)) ),   k = 0 … ell−1.
///   ek.rgswNegS = RGSW(−s)          [from Client::Setup]
///   ek.substKS  = substitution keys  [from Client::Setup]
///
/// Output:
///   rgsw[i] = RGSW(bᵢ),  0 ≤ i < n
///   — a 2ell×2 matrix:
///       row k        = RLWE( bᵢ·(−s)/B^(k+1) )   [top half, via ExternalProduct]
///       row k + ell  = RLWE( bᵢ/B^(k+1)       )   [bottom half, direct from Phase 1]
///
/// Two-phase algorithm:
///   Phase 1 (ExpandRlwe): for each gadget level k, unpack the n individual
///           RLWE ciphertexts RLWE(bᵢ/B^(k+1)) from packed[k].
///   Phase 2 (Assemble):   for each bit i and level k, build the RGSW row:
///           top[k]  ← RGSW(−s) ⊡ RLWE(bᵢ/B^(k+1))   = RLWE(bᵢ·(−s)/B^(k+1))
///           bot[k]  ← RLWE(bᵢ/B^(k+1))                (direct)
inline std::vector<RGSWCt> HomExpand(
    const std::vector<RLWECt>& packed,
    const EvalKey&             ek,
    const Params&              p)
{
    if (packed.size() != p.ell)
        throw std::invalid_argument("HomExpand: packed must have ell ciphertexts");

    // ── Phase 1: expand each of the ell packed ciphertexts ────────────────
    // expanded[k][i] = RLWE( bᵢ / B^(k+1) )
    std::vector<std::vector<RLWECt>> expanded(p.ell);
    for (uint32_t k = 0; k < p.ell; k++) {
        expanded[k] = ExpandRlwe(packed[k], ek, p);
    }

    // ── Phase 2: assemble the RGSW matrix for each bit position ───────────
    std::vector<RGSWCt> rgsw(p.n, RGSWCt(2 * p.ell));

    for (uint32_t i = 0; i < p.n; i++) {
        for (uint32_t k = 0; k < p.ell; k++) {
            const RLWECt& rlwe_ik = expanded[k][i];

            // Top half row k: RGSW(−s) ⊡ RLWE(bᵢ/B^(k+1))
            //   ≈ RLWE( (−s) · bᵢ/B^(k+1) ) = RLWE( bᵢ·(−s)/B^(k+1) )
            rgsw[i][k]        = ExternalProduct(ek.rgswNegS, rlwe_ik, p);

            // Bottom half row k+ell: pass through directly.
            rgsw[i][k + p.ell] = rlwe_ik;
        }
    }
    return rgsw;
}

}  // namespace Server