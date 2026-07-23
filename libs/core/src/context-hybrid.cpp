#include "context-hybrid.h"
#include "factory.h"

namespace {
using namespace core;

/// @brief Get a shared pointer to the RNS parameters
std::shared_ptr<lbcrypto::CryptoParametersRNS> GetRNSParameters(const lbcrypto::CryptoContextImpl<core::Poly>& base) {
    return std::dynamic_pointer_cast<lbcrypto::CryptoParametersRNS>(base.GetCryptoParameters());
}

/// @brief QHat[i] invmod q[i]
std::vector<NativeInteger> ComputeQHatInverses(const std::shared_ptr<lbcrypto::CryptoParametersRNS> params) {
    const auto& Q = params->GetElementParams()->GetModulus();
    const auto& q = params->GetElementParams()->GetParams();

    std::vector<NativeInteger> qHatInv(q.size());

    for (size_t i = 0; i < q.size(); i++) {
        const auto& qi = q[i]->GetModulus();
        BigInteger qHat = Q / BigInteger(qi);
        qHatInv[i] = qHat.ModInverse(qi).ConvertToInt();
    }

    return qHatInv;
}

/// @brief QHat[i] mod p[j]
std::vector<std::vector<NativeInteger>> ComputeQHatModP(const std::shared_ptr<lbcrypto::CryptoParametersRNS> params) {
    const auto& Q = params->GetElementParams()->GetModulus();
    const auto& q = params->GetElementParams()->GetParams();
    const auto& p = params->GetParamsP()->GetParams();

    std::vector<std::vector<NativeInteger>> qHatModP(q.size(), std::vector<NativeInteger>(p.size()));

#pragma omp parallel for
    for (size_t i = 0; i < q.size(); i++) {
        const auto& qi = q[i]->GetModulus();
        BigInteger qHat = Q / BigInteger(qi);

        for (size_t j = 0; j < p.size(); j++) {
            const auto& pj = p[j]->GetModulus();
            qHatModP[i][j] = qHat.Mod(pj).ConvertToInt();
        }
    }

    return qHatModP;
}

/// @brief Thin wrapper around OpenFHE's ApproxModDown (QP -> Q)
Poly ApproxModDown(const std::shared_ptr<lbcrypto::CryptoParametersRNS> params, const Poly& input) {
    return input.ApproxModDown(params->GetElementParams(), params->GetParamsP(), params->GetPInvModq(), params->GetPInvModqPrecon(),
                               params->GetPHatInvModp(), params->GetPHatInvModpPrecon(), params->GetPHatModq(), params->GetModqBarrettMu(),
                               params->GettInvModp(), params->GettInvModpPrecon(), params->GetPlaintextModulus(), params->GettModqPrecon());
};

}  // namespace


namespace core {

ExtendedContextHybridImpl::ExtendedContextHybridImpl(const lbcrypto::CryptoContextImpl<Poly>& base)
    : IExtendedContext(base),
      m_params(GetRNSParameters(base)),
      m_qHatModP(ComputeQHatModP(m_params)),
      m_qHatInv(ComputeQHatInverses(m_params)) {}

// RGSW(m): rows row_i = Z_i + (P·m)·g_i at modulus QP, gadget g = (1, s), so
// phase(row_i) = P·m·g_i + t·e_i with e_i native-small (Z is generated directly
// in QP, neither lifted nor P-scaled).
RGSW ExtendedContextHybridImpl::EncryptRGSW(const PublicKey& pk, const Plaintext& pt) const {
    if (m_pkQP.size() != 2) {
        OPENFHE_THROW("Hybrid EncryptRGSW needs the QP public key; call SetExtendedKey() once after KeyGen.");
    }

    // mG payload: the *message* is lifted by P (the P-limbs of mP are zero).
    Poly mP = Power(pt->GetElement<Poly>());

    RGSW rgsw;
    for (size_t i = 0; i < 2; i++) {
        // Fresh native-error zero-encryption directly at modulus QP. Crucially the
        // error is NOT scaled by P (unlike the message), so ApproxModDown in the
        // external product divides the cross-term t*<c,e> down by a factor P. This
        // is the actual GHS noise reduction; the previous P-scaling of Z cancelled
        // it. The cost is that Z's `a` is now uniform mod QP -> security is mod QP.
        auto E = EncryptZeroQP();

        // Keep correct CryptoContext without having a ciphertext to clone
        auto ct = std::make_shared<lbcrypto::CiphertextImpl<Poly>>(pk);
        ct->SetEncodingType(pt->GetEncodingType());
        ct->SetElements({std::move(E[0]), std::move(E[1])});
        rgsw.push_back(std::move(ct));
    }

    // Z + mG = Z + P(m): message lifted by P, error left at native scale.
    rgsw[0]->GetElements()[0] += mP;
    rgsw[1]->GetElements()[1] += mP;

    return rgsw;
}

RGSW ExtendedContextHybridImpl::MakePublicRGSW(const PublicKey& pk, const Plaintext& pt) const {
    const auto paramsQP = m_params->GetParamsQP();

    // Noiseless "public" RGSW: the P-lifted message on the gadget diagonal, no Z.
    Poly mP = Power(pt->GetElement<Poly>());

    RGSW rgsw;
    for (size_t i = 0; i < 2; i++) {
        Poly c0(paramsQP, Format::EVALUATION, true);
        Poly c1(paramsQP, Format::EVALUATION, true);

        auto ct = std::make_shared<lbcrypto::CiphertextImpl<Poly>>(pk);
        ct->SetEncodingType(pt->GetEncodingType());
        ct->SetElements({std::move(c0), std::move(c1)});
        rgsw.push_back(std::move(ct));
    }

    rgsw[0]->GetElements()[0] += mP;
    rgsw[1]->GetElements()[1] += mP;

    return rgsw;
}

void ExtendedContextHybridImpl::SetExtendedKey(const lbcrypto::KeyPair<Poly>& keys) {
    const auto paramsQP = m_params->GetParamsQP();
    const auto& pparamsQP = paramsQP->GetParams();
    const auto ns = m_params->GetNoiseScale();
    auto dgg = m_params->GetDiscreteGaussianGenerator();

    const uint32_t sizeQ = m_params->GetElementParams()->GetParams().size();
    const uint32_t sizeQP = pparamsQP.size();

    // Extend the secret key s from basis Q to basis QP: copy the Q-limbs, and for
    // each P-limb re-embed the (small, ternary) coefficients of s mod p_j.
    const Poly& s = keys.secretKey->GetPrivateElement();
    Poly sExt(paramsQP, Format::EVALUATION, true);

    NativePoly s0 = s.GetElementAtIndex(0);
    s0.SetFormat(Format::COEFFICIENT);
    for (uint32_t i = 0; i < sizeQP; i++) {
        if (i < sizeQ) {
            auto tmp = s.GetElementAtIndex(i);
            tmp.SetFormat(Format::EVALUATION);
            sExt.SetElementAtIndex(i, std::move(tmp));
        } else {
            auto tmp = s0;
            tmp.SwitchModulus(pparamsQP[i]->GetModulus(), pparamsQP[i]->GetRootOfUnity(), 0, 0);
            tmp.SetFormat(Format::EVALUATION);
            sExt.SetElementAtIndex(i, std::move(tmp));
        }
    }

    // Genuine RLWE public key at modulus QP: (b = -a*s + t*e, a), a uniform mod QP.
    Poly::DugType dug;
    Poly a(dug, paramsQP, Format::EVALUATION);
    Poly e(dgg, paramsQP, Format::EVALUATION);
    Poly b = -(a * sExt) + ns * e;

    m_pkQP = {std::move(b), std::move(a)};
}

std::vector<Poly> ExtendedContextHybridImpl::EncryptZeroQP() const {
    const auto paramsQP = m_params->GetParamsQP();
    const auto ns = m_params->GetNoiseScale();
    auto dgg = m_params->GetDiscreteGaussianGenerator();

    // Standard public-key encryption of zero, done directly in QP with pk_QP.
    // Phase = c0 + c1*s = t*(u*e_pk + e0 + e1*s), i.e. small native error.
    Poly::TugType tug;
    Poly u(tug, paramsQP, Format::EVALUATION);
    Poly e0(dgg, paramsQP, Format::EVALUATION);
    Poly e1(dgg, paramsQP, Format::EVALUATION);

    Poly c0 = m_pkQP[0] * u + ns * e0;
    Poly c1 = m_pkQP[1] * u + ns * e1;

    return {std::move(c0), std::move(c1)};
}

// RLWE(m_x) ⊠ RGSW(m_y) -> RLWE(m_x·m_y).
//
// With d_i = Lift(c_i) = c_i + Q·u_i and rows phase P·m_y·g_i + t·e_i:
//   phase(out) = P·m_y·(m_x + t·e_c) + P·m_y·Q·(u_0 + u_1·s) + t·(d_0·e_0 + d_1·e_1)
//              = P·(m_x·m_y) + t·(P·m_y·e_c + d·e)        (mod QP, since P·Q ≡ 0)
// i.e. RLWE(m_x·m_y·P) in QP. ApproxModDown divides by P:
//   phase(result) = m_x·m_y + t·(m_y·e_c + d·e/P + r)     (mod Q)
// The cross term d·e/P is native-small because P ≈ Q — this is why the input is
// lifted UNSCALED while the RGSW message carries the single factor of P.
RLWE ExtendedContextHybridImpl::EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const {
    auto c = rlwe->GetElements();

    c[0].SetFormat(Format::EVALUATION);
    c[1].SetFormat(Format::EVALUATION);

    const auto d0 = Lift(c[0]);
    const auto d1 = Lift(c[1]);

    Poly out0(m_params->GetParamsQP(), Format::EVALUATION, true);
    Poly out1(m_params->GetParamsQP(), Format::EVALUATION, true);

    out0 += (d0 * rgsw[0]->GetElements()[0]);
    out1 += (d0 * rgsw[0]->GetElements()[1]);
    out0 += (d1 * rgsw[1]->GetElements()[0]);
    out1 += (d1 * rgsw[1]->GetElements()[1]);

    auto result = rlwe->Clone();
    result->GetElements()[0] = ApproxModDown(m_params, out0);
    result->GetElements()[1] = ApproxModDown(m_params, out1);

    return result;
}

RGSW ExtendedContextHybridImpl::EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const {
    // TODO: The straightforward per-row external product does not work here: modding
    // a row down re-amplifies the rounding by P, and skipping the ModDown leaves the
    // d·e cross term undivided — both blow the noise budget. Needs a dedicated design.
    OPENFHE_THROW("EvalInternalProduct is not implemented for the hybrid context yet");
    // RGSW result;
    // for(auto& rlwe :  lhs) {
    //     auto c = rlwe->GetElements();

    //     c[0].SetFormat(Format::EVALUATION);
    //     c[1].SetFormat(Format::EVALUATION);

    //     const auto d0 = Lift(c[0]);
    //     const auto d1 = Lift(c[1]);

    //     Poly out0(m_params->GetParamsQP(), Format::EVALUATION, true);
    //     Poly out1(m_params->GetParamsQP(), Format::EVALUATION, true);

    //     out0 += (d0 * rgsw[0]->GetElements()[0]);
    //     out1 += (d0 * rgsw[0]->GetElements()[1]);
    //     out0 += (d1 * rgsw[1]->GetElements()[0]);
    //     out1 += (d1 * rgsw[1]->GetElements()[1]);

    //     auto result = rlwe->Clone();
    //     result->GetElements()[0] = ApproxModDown(m_params, out0);
    //     result->GetElements()[1] = ApproxModDown(m_params, out1);

    //     return result;
    // }
    // return result;
}

//-----------//
// Internals //
//-----------//


// Exact multiply-by-P lift Q -> QP: represents P·x mod QP (Q-limbs scaled by
// P mod q_i, P-limbs ≡ 0). Identity: Power(x) ≡ P·Lift(x) (mod QP) — the Q·u
// junk of the fast base extension dies because P·Q ≡ 0 (mod QP). So Power is
// the P-scaled (and cheaper: no base extension, no format change) form of the
// one conceptual lift.
Poly ExtendedContextHybridImpl::Power(const Poly& input) const {
    const auto QP = m_params->GetParamsQP();
    const auto P = m_params->GetParamsP()->GetModulus();
    const auto q = m_params->GetElementParams()->GetParams();

    Poly m(QP, Format::EVALUATION, true);

    const auto& inputLimbs = input.GetAllElements();
    auto& mLimbs = m.GetAllElements();

    for (uint32_t k = 0; k < q.size(); k++) {
        const auto& qk = q[k]->GetModulus();
        NativeInteger pMod = P.Mod(qk).ConvertToInt();

        // Multiply the k-th limb by (P mod qk)
        for (uint32_t col = 0; col < inputLimbs[k].GetLength(); col++) {
            mLimbs[k][col] = inputLimbs[k][col].ModMul(pMod, qk);
        }
    }

    // Note: the last limb(s) are mod p_i and so are always 0, therefore skip them
    return m;
};

// Unscaled lift Q -> QP via fast base extension: represents x + Q·u for a small
// overflow u (0 ≤ u < #Q-limbs). The Q·u term is harmless in the external product
// because it is multiplied by the P-scaled RGSW message (P·Q ≡ 0 mod QP).
Poly ExtendedContextHybridImpl::Lift(const Poly& input) const {
    const auto QP = m_params->GetParamsQP();

    Poly result(QP, Format::COEFFICIENT, true);
    Poly inputCoeff = input;
    inputCoeff.SetFormat(Format::COEFFICIENT);

    const auto& in_limbs = inputCoeff.GetAllElements();
    auto& res_limbs = result.GetAllElements();

    uint32_t numQ = m_params->GetElementParams()->GetParams().size();
    uint32_t numP = m_params->GetParamsP()->GetParams().size();
    uint32_t n = m_params->GetElementParams()->GetRingDimension();

    // Copy Q-towers (O(L*N)) and pre-scale by qInv (saves cache-accesses)
    std::vector<NativePoly> v(numQ);
    for (uint32_t i = 0; i < numQ; i++) {
        res_limbs[i] = in_limbs[i];
        v[i] = in_limbs[i].Times(m_qHatInv[i]);
    }

// Fast Base Extension (Q -> QP)
#pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(numP))
    for (uint32_t j = 0; j < numP; j++) {
        uint32_t target_idx = numQ + j;
        const auto& pj = m_params->GetParamsP()->GetParams()[j]->GetModulus();
        auto& target_poly = res_limbs[target_idx];

        for (uint32_t i = 0; i < numQ; i++) {
            const auto& qHat = m_qHatModP[i][j];
            const auto& source_poly = v[i];

            for (uint32_t col = 0; col < n; col++) {
                // Fused Multiply-Add: res = (res + source * qHat) mod pj
                NativeInteger term = source_poly[col].ModMul(qHat, pj);
                target_poly[col] = target_poly[col].ModAdd(term, pj);
            }
        }
    }

    result.SetFormat(Format::EVALUATION);
    return result;
};

//------//
//      //
//------//

RGSW ExtendedContextHybridImpl::EvalAddRGSW(const RGSW& lhs, const RGSW& rhs) const {
    if (lhs.size() != 2 || rhs.size() != 2) {
        OPENFHE_THROW("EvalAddRGSW expects 2x2 RGSW structure");
    }

    RGSW result;
    result.reserve(2);

    for (size_t row = 0; row < 2; row++) {
        // Clone exactly copies the correct embedded CryptoContext pointer
        auto out = lhs[row]->Clone();

        auto cL = lhs[row]->GetElements();
        auto cR = rhs[row]->GetElements();

        // Direct polynomial addition
        out->SetElements({cL[0] + cR[0], cL[1] + cR[1]});
        result.push_back(std::move(out));
    }

    return result;
}

RGSW ExtendedContextHybridImpl::EvalSubRGSW(const RGSW& lhs, const RGSW& rhs) const {
    if (lhs.size() != 2 || rhs.size() != 2) {
        OPENFHE_THROW("EvalSubRGSW expects 2x2 RGSW structure");
    }

    RGSW result;
    result.reserve(2);

    for (size_t row = 0; row < 2; row++) {
        // Clone exactly copies the correct embedded CryptoContext pointer
        auto out = lhs[row]->Clone();

        auto cL = lhs[row]->GetElements();
        auto cR = rhs[row]->GetElements();

        // Direct polynomial subtraction
        out->SetElements({cL[0] - cR[0], cL[1] - cR[1]});
        result.push_back(std::move(out));
    }

    return result;
}

RGSW ExtendedContextHybridImpl::EvalMultRGSW(const RGSW& rgsw, const Plaintext& pt) const {
    if (rgsw.size() != 2) {
        OPENFHE_THROW("EvalMultRGSW expects 2x2 RGSW structure");
    }

    const auto paramsQP = m_params->GetParamsQP();

    // 1. Extract plaintext polynomial in Q
    Poly p_Q = pt->GetElement<Poly>();
    p_Q.SetFormat(Format::COEFFICIENT);

    // 2. Fast bypass to lift to QP
    // Because plaintext values are strictly bounded by t (which is much smaller than q0),
    // they are purely positive integers. We can safely copy them directly.
    NativePoly p_first = p_Q.GetElementAtIndex(0);
    uint32_t ringDim = p_first.GetLength();

    std::vector<NativePoly> p_limbs;
    for (size_t j = 0; j < paramsQP->GetParams().size(); j++) {
        auto limbParams = paramsQP->GetParams()[j];
        NativePoly limb(limbParams, Format::COEFFICIENT, true);

        for (size_t i = 0; i < ringDim; i++) {
            limb[i] = p_first[i];
        }
        p_limbs.push_back(std::move(limb));
    }

    Poly p_QP(p_limbs);

    // Switch plaintext to EVALUATION format for element-wise multiplication
    p_QP.SetFormat(Format::EVALUATION);

    // 3. Multiply every element of the RGSW matrix by the plaintext polynomial
    RGSW result;
    result.reserve(2);

    for (size_t row = 0; row < 2; row++) {
        // Clone preserves the CryptoContext pointer and Encoding Type
        auto out = rgsw[row]->Clone();
        auto c = rgsw[row]->GetElements();

        // Direct polynomial multiplication
        out->SetElements({c[0] * p_QP, c[1] * p_QP});
        result.push_back(std::move(out));
    }

    return result;
}

//-------------------------//
// OpenFHE-Context Factory //
//-------------------------//

ExtendedContext GenContextHybrid(const lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS>& parameters) {
    auto baseCC = lbcrypto::GenCryptoContext(parameters);
    auto ext = std::make_shared<ExtendedContextHybridImpl>(*baseCC);
    factory::FactoryRegistrar<Poly>::Add(ext);
    return ext;
}

}  // namespace core