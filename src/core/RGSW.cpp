#include "core/RGSW.h"

#include <cassert>
#include <cmath>

// Format is a global enum defined in openfhe/core/utils/inttypes.h:
//   enum Format { EVALUATION = 0, COEFFICIENT = 1 };
// It is NOT in the lbcrypto namespace.

namespace core {

// ---- RGSWParams::Make -------------------------------------------------------

RGSWParams RGSWParams::Make(uint32_t N, NativeInteger Q, uint32_t baseB) {
    RGSWParams p;
    p.N     = N;
    p.Q     = Q;
    p.baseB = baseB;

    // ILNativeParams(cyclotomic_order, modulus): cyclotomic order = 2*N for X^N+1.
    // The root of unity is computed automatically.
    p.polyParams = std::make_shared<lbcrypto::ILNativeParams>(2 * N, Q);

    // digitsG = ceil(log_B(Q)) = ceil(log2(Q) / log2(B))
    double logQ = std::log2(Q.ConvertToDouble());
    double logB = std::log2(static_cast<double>(baseB));
    p.digitsG   = static_cast<uint32_t>(std::ceil(logQ / logB));

    // Gpower[j] = B^j mod Q,  j = 0 .. digitsG-1
    p.Gpower.resize(p.digitsG);
    p.Gpower[0] = NativeInteger(1);
    NativeInteger Bni(baseB);
    for (uint32_t j = 1; j < p.digitsG; ++j)
        p.Gpower[j] = p.Gpower[j - 1].ModMulFast(Bni, Q);

    return p;
}

// ---- RGSWCt constructor -----------------------------------------------------

RGSWCt::RGSWCt(uint32_t digitsG, const std::shared_ptr<lbcrypto::ILNativeParams>& pp) {
    rows.resize(2 * digitsG);
    for (auto& row : rows) {
        row[0] = NativePoly(pp, Format::EVALUATION, true);
        row[1] = NativePoly(pp, Format::EVALUATION, true);
    }
}

// ---- Key generation ---------------------------------------------------------

NativePoly RGSWKeyGen(const RGSWParams& p) {
    lbcrypto::TernaryUniformGeneratorImpl<lbcrypto::NativeVector> tug;
    NativePoly sk(p.polyParams);
    sk.SetValues(tug.GenerateVector(p.N, p.Q), Format::COEFFICIENT);
    return sk; // COEFFICIENT format
}

// ---- RLWE encrypt / decrypt -------------------------------------------------

RLWECt RLWEEncrypt(const RGSWParams& p, const NativePoly& sk, const NativePoly& mu,
                   NativeInteger scaling) {
    lbcrypto::DiscreteUniformGeneratorImpl<lbcrypto::NativeVector> dug;
    lbcrypto::DiscreteGaussianGeneratorImpl<lbcrypto::NativeVector> dgg(3.19);

    // a: uniform random polynomial (COEFFICIENT)
    NativePoly a(dug, p.polyParams, Format::COEFFICIENT);

    // e: small Gaussian noise (COEFFICIENT)
    NativePoly e(dgg, p.polyParams, Format::COEFFICIENT);

    // b = a*sk  in EVALUATION, then convert back to COEFFICIENT
    NativePoly aNTT = a;
    aNTT.SetFormat(Format::EVALUATION);
    NativePoly skNTT = sk;
    skNTT.SetFormat(Format::EVALUATION);

    NativePoly b = aNTT * skNTT; // EVALUATION
    b.SetFormat(Format::COEFFICIENT);

    // b += e + mu*scaling  (all mod Q, COEFFICIENT domain)
    b += e;
    for (uint32_t k = 0; k < p.N; ++k)
        b[k].ModAddFastEq(mu[k].ModMulFast(scaling, p.Q), p.Q);

    // Return in EVALUATION format
    a.SetFormat(Format::EVALUATION);
    b.SetFormat(Format::EVALUATION);

    return lbcrypto::RLWECiphertextImpl({a, b});
}

NativePoly RLWEDecrypt(const RGSWParams& p, const NativePoly& sk, const RLWECt& ct) {
    NativePoly skNTT = sk;
    skNTT.SetFormat(Format::EVALUATION);

    const auto& elems = ct.GetElements();
    NativePoly phase  = elems[1] - elems[0] * skNTT; // EVALUATION
    phase.SetFormat(Format::COEFFICIENT);
    return phase; // ≈ mu*scaling + small error
}

// ---- RGSW encrypt -----------------------------------------------------------

RGSWCt RGSWEncrypt(const RGSWParams& p, const NativePoly& sk, const NativePoly& mu) {
    lbcrypto::DiscreteUniformGeneratorImpl<lbcrypto::NativeVector> dug;
    lbcrypto::DiscreteGaussianGeneratorImpl<lbcrypto::NativeVector> dgg(3.19);

    NativePoly skNTT = sk;
    skNTT.SetFormat(Format::EVALUATION);

    RGSWCt C(p.digitsG, p.polyParams);

    for (uint32_t i = 0; i < 2 * p.digitsG; ++i) {
        const uint32_t j   = i / 2; // gadget level → Gpower[j]
        const uint32_t col = i % 2; // which component carries μ·Gpower[j]

        // a: random (COEFFICIENT).  aNTT: copy of the ORIGINAL a (before gadget).
        NativePoly a(dug, p.polyParams, Format::COEFFICIENT);
        NativePoly aNTT = a;
        aNTT.SetFormat(Format::EVALUATION); // NTT(a_original)

        // e (will become b = a_original*sk + e): Gaussian noise (COEFFICIENT)
        NativePoly e(dgg, p.polyParams, Format::COEFFICIENT);

        // Add μ·Gpower[j] coefficient-wise to the target component (COEFFICIENT)
        //   col=0 → gadget in a   (row decrypts to ≈ −μ·Gpower[j]·sk)
        //   col=1 → gadget in e/b (row decrypts to ≈  μ·Gpower[j])
        NativePoly& target = (col == 0) ? a : e;
        for (uint32_t k = 0; k < p.N; ++k)
            target[k].ModAddFastEq(mu[k].ModMulFast(p.Gpower[j], p.Q), p.Q);

        // b = a_original*sk + e(+gadget if col=1)
        a.SetFormat(Format::EVALUATION);
        e.SetFormat(Format::EVALUATION);
        e += aNTT * skNTT; // e is now b

        C.rows[i] = {a, e};
    }

    return C;
}

// ---- Gadget decomposition ---------------------------------------------------

std::vector<NativePoly> GadgetDecompose(const RGSWParams& p, const RLWECt& d) {
    // Work on COEFFICIENT copies
    std::vector<NativePoly> ct = d.GetElements();
    ct[0].SetFormat(Format::COEFFICIENT);
    ct[1].SetFormat(Format::COEFFICIENT);

    // 2*digitsG zero polynomials in COEFFICIENT format
    std::vector<NativePoly> out(2 * p.digitsG,
                                NativePoly(p.polyParams, Format::COEFFICIENT, true));

    const uint64_t Q_u64   = p.Q.ConvertToInt<uint64_t>();
    const uint64_t QHalf   = Q_u64 >> 1;
    const int64_t  Q_int   = static_cast<int64_t>(Q_u64);
    const int64_t  gBits   = static_cast<int64_t>(__builtin_ctz(p.baseB));
    const int64_t  gBitsMaxBits = 64 - gBits;

    for (uint32_t k = 0; k < p.N; ++k) {
        uint64_t t0 = ct[0][k].ConvertToInt<uint64_t>();
        int64_t  d0 = static_cast<int64_t>(t0 < QHalf ? t0 : t0 - Q_u64);

        uint64_t t1 = ct[1][k].ConvertToInt<uint64_t>();
        int64_t  d1 = static_cast<int64_t>(t1 < QHalf ? t1 : t1 - Q_u64);

        // Full digitsG digits, no initial skip (unlike binfhe's approximate version)
        for (uint32_t j = 0; j < p.digitsG; ++j) {
            int64_t r0 = (d0 << gBitsMaxBits) >> gBitsMaxBits; // sign-extend lowest gBits bits
            d0         = (d0 - r0) >> gBits;
            if (r0 < 0)
                r0 += Q_int;
            out[2 * j + 0][k] += static_cast<uint64_t>(r0);

            int64_t r1 = (d1 << gBitsMaxBits) >> gBitsMaxBits;
            d1         = (d1 - r1) >> gBits;
            if (r1 < 0)
                r1 += Q_int;
            out[2 * j + 1][k] += static_cast<uint64_t>(r1);
        }
    }

    return out; // COEFFICIENT format
}

// ---- External product -------------------------------------------------------

RLWECt ExternalProduct(const RGSWParams& p, const RGSWCt& C, const RLWECt& d) {
    // 1. Gadget-decompose d  (2*digitsG polys in COEFFICIENT)
    auto dct = GadgetDecompose(p, d);

    // 2. Convert each digit to EVALUATION for multiplication
    for (auto& poly : dct)
        poly.SetFormat(Format::EVALUATION);

    // 3. Matrix-vector product: result[j] = Σ_i  dct[i] * C.rows[i][j]
    NativePoly res0(p.polyParams, Format::EVALUATION, true);
    NativePoly res1(p.polyParams, Format::EVALUATION, true);

    for (uint32_t i = 0; i < 2 * p.digitsG; ++i) {
        res0 += dct[i] * C.rows[i][0];
        res1 += dct[i] * C.rows[i][1];
    }

    return lbcrypto::RLWECiphertextImpl({res0, res1});
}

// ---- CMux -------------------------------------------------------------------

RLWECt CMux(const RGSWParams& p, const RGSWCt& C, const RLWECt& d1, const RLWECt& d0) {
    // diff = d1 - d0  (EVALUATION)
    const auto& e1 = d1.GetElements();
    const auto& e0 = d0.GetElements();
    lbcrypto::RLWECiphertextImpl diff({e1[0] - e0[0], e1[1] - e0[1]});

    // result = C ⊡ diff + d0
    RLWECt result = ExternalProduct(p, C, diff);
    result.GetElements()[0] += e0[0];
    result.GetElements()[1] += e0[1];
    return result;
}

} // namespace core
