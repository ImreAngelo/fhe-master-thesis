#include "context-hybrid.h"
#include "factory.h"

namespace {
using namespace spar;

/// @brief Get a shared pointer to the RNS parameters
std::shared_ptr<lbcrypto::CryptoParametersRNS> GetRNSParameters(const lbcrypto::CryptoContextImpl<spar::Poly>& base) {
    return std::dynamic_pointer_cast<lbcrypto::CryptoParametersRNS>(base.GetCryptoParameters());
}

/// @brief QHat[i] mod q[i]
std::vector<NativeInteger> ComputeQHatInverses(const std::shared_ptr<lbcrypto::CryptoParametersRNS> params) {
    const auto& Q = params->GetElementParams()->GetModulus();
    const auto& q = params->GetElementParams()->GetParams();

    std::vector<NativeInteger> qHatInv(q.size());

    // Too small to use threads
    // #pragma omp parallel for
    for(size_t i = 0; i < q.size(); i++) {
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

    // Too small to use threads
    // #pragma omp parallel for
    for(size_t i = 0; i < q.size(); i++) {
        const auto& qi = q[i]->GetModulus();
        BigInteger qHat = Q / BigInteger(qi);

        for(size_t j = 0; j < p.size(); j++) {
            const auto& pj = p[j]->GetModulus();
            qHatModP[i][j] = qHat.Mod(pj).ConvertToInt();
        }
    }

    return qHatModP;
}

/// @brief Thin wrapper around OpenFHE's ApproxModDown (QP -> Q)
Poly ApproxModDown(const std::shared_ptr<lbcrypto::CryptoParametersRNS> params, const Poly& input) {
    return input.ApproxModDown(params->GetElementParams(), params->GetParamsP(), params->GetPInvModq(),
        params->GetPInvModqPrecon(), params->GetPHatInvModp(),
        params->GetPHatInvModpPrecon(), params->GetPHatModq(),
        params->GetModqBarrettMu(), params->GettInvModp(),
        params->GettInvModpPrecon(), params->GetPlaintextModulus(), params->GettModqPrecon());
};

} // namespace


namespace spar {

ExtendedContextHybridImpl::ExtendedContextHybridImpl(const lbcrypto::CryptoContextImpl<Poly>& base)
  : IExtendedContext(base), m_params(GetRNSParameters(base)), m_qHatModP(ComputeQHatModP(m_params)), m_qHatInv(ComputeQHatInverses(m_params))
{}

// TODO: Include noise!!
RGSW ExtendedContextHybridImpl::EncryptRGSW(const PublicKey& pk, const Plaintext& pt, const bool noisy) const {
    const auto paramsQP = m_params->GetParamsQP();

    // Scale by P
    Poly mP = Power(pt->GetElement<Poly>());

    RGSW rgsw;
    for(size_t i = 0; i < 2; i++) {
        // TODO: This contains no noise!!! (not secure in production)
        Poly c0(paramsQP, Format::EVALUATION, true);
        Poly c1(paramsQP, Format::EVALUATION, true);

        // Keep correct CryptoContext without having a ciphertext to clone
        auto ct = std::make_shared<lbcrypto::CiphertextImpl<Poly>>(pk);
        ct->SetEncodingType(pt->GetEncodingType());
        ct->SetElements({c0, c1});
        rgsw.push_back(ct);
    }

    // Z + mG = Z + P(m) in hybrid
    rgsw[0]->GetElements()[0] += mP;
    rgsw[1]->GetElements()[1] += mP;

    return rgsw;
}

RLWE ExtendedContextHybridImpl::EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const {
    auto c = rlwe->GetElements();

    c[0].SetFormat(Format::EVALUATION);
    c[1].SetFormat(Format::EVALUATION);

    const auto d0 = Decompose(c[0]);
    const auto d1 = Decompose(c[1]);

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
    RGSW result;
    result.reserve(2);

    for (size_t row = 0; row < 2; row++) {
        auto c = lhs[row]->GetElements();

        // FIX: Modulus switch down from QP to Q FIRST!
        // This drops the factor of P that 'lhs' currently encrypts.
        Poly c0_Q = ApproxModDown(m_params, c[0]);
        Poly c1_Q = ApproxModDown(m_params, c[1]);

        c0_Q.SetFormat(Format::EVALUATION);
        c1_Q.SetFormat(Format::EVALUATION);

        // Gadget decomposition Q -> QP
        Poly d0 = Decompose(c0_Q);
        Poly d1 = Decompose(c1_Q);

        // Output row in QP
        Poly out0(m_params->GetParamsQP(), Format::EVALUATION, true);
        Poly out1(m_params->GetParamsQP(), Format::EVALUATION, true);

        // Standard external product
        out0 += d0 * rhs[0]->GetElements()[0];
        out1 += d0 * rhs[0]->GetElements()[1];

        out0 += d1 * rhs[1]->GetElements()[0];
        out1 += d1 * rhs[1]->GetElements()[1];

        // Build new RGSW row directly in QP
        auto ct = lhs[row]->Clone();
        ct->SetElements({std::move(out0), std::move(out1)});

        result.push_back(std::move(ct));
    }

    return result;
}

//-----------//
// Internals //
//-----------//


// TODO: Do not pass const, modify directly
Poly ExtendedContextHybridImpl::Power(const Poly& input) const
{
    const auto QP = m_params->GetParamsQP();
    const auto P = m_params->GetParamsP()->GetModulus();
    const auto q = m_params->GetElementParams()->GetParams();

    Poly m(QP, Format::EVALUATION, true);

    const auto& inputLimbs = input.GetAllElements();
    auto& mLimbs = m.GetAllElements();

    for(uint32_t k = 0; k < q.size(); k++) {
        const auto& qk = q[k]->GetModulus();
        NativeInteger pMod = P.Mod(qk).ConvertToInt();

        // Multiply the k-th limb by (P mod qk)
        for(uint32_t col = 0; col < inputLimbs[k].GetLength(); col++) {
            mLimbs[k][col] = inputLimbs[k][col].ModMul(pMod, qk);
        }
    }

    // Note: the last limb(s) are mod p_i and so are always 0, therefore skip them
    return m;
};

// TODO: Do not pass const, modify directly
Poly ExtendedContextHybridImpl::Decompose(const Poly& input) const
{
    const auto QP = m_params->GetParamsQP();

    // Coefficient mode required?
    Poly result(QP, Format::COEFFICIENT, true);
    Poly inputCoeff = input;
    inputCoeff.SetFormat(Format::COEFFICIENT);

    const auto& in_limbs = inputCoeff.GetAllElements();
    auto& res_limbs = result.GetAllElements();

    uint32_t numQ =  m_params->GetElementParams()->GetParams().size();
    uint32_t numP = m_params->GetParamsP()->GetParams().size();
    uint32_t n = m_params->GetElementParams()->GetRingDimension();

    // Copy Q-towers (O(L*N)) and pre-scale by qInv (saves cache-accesses)
    std::vector<NativePoly> v(numQ);
    for(uint32_t i = 0; i < numQ; i++) {
        res_limbs[i] = in_limbs[i];
        v[i] = in_limbs[i].Times(m_qHatInv[i]);
    }

    // Fast Base Extension (Q -> QP)
    // TODO: Re-enable multi-threading
    #pragma omp parallel for num_threads(lbcrypto::OpenFHEParallelControls.GetThreadLimit(numP))
    for(uint32_t j = 0; j < numP; j++) {
        uint32_t target_idx = numQ + j;
        const auto& pj = m_params->GetParamsP()->GetParams()[j]->GetModulus();
        auto& target_poly = res_limbs[target_idx];

        for(uint32_t i = 0; i < numQ; i++) {
            const auto& qHat = m_qHatModP[i][j];
            const auto& source_poly = v[i];

            for(uint32_t col = 0; col < n; col++) {
                // Fused Multiply-Add: res = (res + source * qHat) mod pj
                NativeInteger term = source_poly[col].ModMul(qHat, pj);
                target_poly[col] = target_poly[col].ModAdd(term, pj);
            }
        }
    }

    result.SetFormat(Format::EVALUATION);
    return result;
};

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

} // namespace spar