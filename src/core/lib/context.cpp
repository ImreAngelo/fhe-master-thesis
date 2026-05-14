#include "../include/context.h"
#include "../../utils/logging.h"

using namespace Context;


ExtendedCryptoContextImpl::ExtendedCryptoContextImpl(const CryptoContextImpl<DCRTPoly>& base)
    : CryptoContextImpl<DCRTPoly>(base), 
        m_params(std::dynamic_pointer_cast<CryptoParametersRNS>(base.GetCryptoParameters())) 
{
    // TODO: Refactor
    const auto& Q_limbs = m_params->GetElementParams()->GetParams();
    const auto& P_limbs = m_params->GetParamsP()->GetParams();
    const auto Q_mod = m_params->GetElementParams()->GetModulus();
    const auto P_mod = m_params->GetParamsP()->GetModulus();

    uint32_t numQ = Q_limbs.size();
    uint32_t numP = P_limbs.size();

    DEBUG_PRINT("Created ExtendedCryptoContext with #Q = " << numQ << ", #P " << numP);

    m_qHatModP.resize(numQ, std::vector<NativeInteger>(numP));
    m_qInv.resize(numQ);

    for (uint32_t i = 0; i < numQ; i++) {
        const auto& qi = Q_limbs[i]->GetModulus();
        BigInteger qHat = Q_mod / BigInteger(qi);
        
        m_qInv[i] = qHat.ModInverse(qi).ConvertToInt();

        for (uint32_t j = 0; j < numP; j++) {
            const auto& pj = P_limbs[j]->GetModulus();
            m_qHatModP[i][j] = qHat.Mod(pj).ConvertToInt();
        }
    }
}

// TODO: Do not pass const, modify directly
DCRTPoly ExtendedCryptoContextImpl::Power(const DCRTPoly& input) const 
{
    const auto QP = m_params->GetParamsQP();
    const auto P = m_params->GetParamsP()->GetModulus();
    const auto q = m_params->GetElementParams()->GetParams();
    
    DCRTPoly m(QP, Format::EVALUATION, true);

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

// TODO: DO not pass const, modify directly
DCRTPoly ExtendedCryptoContextImpl::Decompose(const DCRTPoly& input) const 
{
    const auto QP = m_params->GetParamsQP();
    
    // Coefficient mode required
    DCRTPoly result(QP, Format::COEFFICIENT, true);
    DCRTPoly inputCoeff = input;
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
        v[i] = in_limbs[i].Times(m_qInv[i]);
    }
    
    // Fast Base Extension (Q -> QP)
    // TODO: Re-enable multi-threading in project
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numP))
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

// Approximate mod down QP -> Q
// NOTE: Might need exact mod down for BGV
DCRTPoly ExtendedCryptoContextImpl::ApproxModDown(const DCRTPoly& input) const {
    return input.ApproxModDown(m_params->GetElementParams(), m_params->GetParamsP(), m_params->GetPInvModq(),
        m_params->GetPInvModqPrecon(), m_params->GetPHatInvModp(),
        m_params->GetPHatInvModpPrecon(), m_params->GetPHatModq(),
        m_params->GetModqBarrettMu(), m_params->GettInvModp(),
        m_params->GettInvModpPrecon(), m_params->GetPlaintextModulus(), m_params->GettModqPrecon());
};

std::vector<DCRTPoly> ExtendedCryptoContextImpl::EncryptZeroQP(const PrivateKey<DCRTPoly>& secretKey) const
{
    const auto paramsQP = m_params->GetParamsQP();
    const auto& paramsQP_vec = paramsQP->GetParams();
    const auto ns = m_params->GetNoiseScale();

    // Lift secret key s from Q to QP. s has small (e.g. ternary) coefficients,
    // so we copy the Q-towers verbatim and obtain the P-towers via SwitchModulus
    // on the (small-valued) coefficient form of the first Q-tower.
    const DCRTPoly& sQ = secretKey->GetPrivateElement();
    const uint32_t sizeQ  = sQ.GetParams()->GetParams().size();
    const uint32_t sizeQP = paramsQP_vec.size();

    DCRTPoly s(paramsQP, Format::EVALUATION, true);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        s.SetElementAtIndex(i, sQ.GetElementAtIndex(i));
    }
    auto s0 = sQ.GetElementAtIndex(0);
    s0.SetFormat(Format::COEFFICIENT);
    for (uint32_t i = sizeQ; i < sizeQP; ++i) {
        auto tmp = s0;
        tmp.SwitchModulus(paramsQP_vec[i]->GetModulus(), paramsQP_vec[i]->GetRootOfUnity(), 0, 0);
        tmp.SetFormat(Format::EVALUATION);
        s.SetElementAtIndex(i, std::move(tmp));
    }

    // Fresh uniform `a` and Gaussian `e` directly in QP
    typename DCRTPoly::DugType dug;
    const auto& dgg = m_params->GetDiscreteGaussianGenerator();
    DEBUG_PRINT("Standard deviation: " << dgg.GetStd());
    DCRTPoly a(dug, paramsQP, Format::EVALUATION);
    DCRTPoly e(dgg, paramsQP, Format::EVALUATION);

    // BGV-style zero encryption: c0 = a*s + ns*e, c1 = -a  =>  c0 + c1*s = ns*e
    DCRTPoly c0 = a * s + e * NativeInteger(ns);
    DCRTPoly c1 = a.Negate();

    return {std::move(c0), std::move(c1)};
}

std::vector<Ciphertext<DCRTPoly>> ExtendedCryptoContextImpl::EncryptRGSW(const PrivateKey<DCRTPoly>& secretKey, const Plaintext& m) const
{
    // Scale by P
    DCRTPoly mP = Power(m->GetElement<DCRTPoly>());

    std::vector<Ciphertext<DCRTPoly>> rgsw;
    rgsw.reserve(2);
    for(size_t i = 0; i < 2; i++) {
        auto z = EncryptZeroQP(secretKey);
        auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(secretKey);
        ct->SetEncodingType(m->GetEncodingType());
        ct->SetElements({std::move(z[0]), std::move(z[1])});
        rgsw.push_back(std::move(ct));
    }

    // Z + mG = Z + P(m) in hybrid
    rgsw[0]->GetElements()[0] += mP;
    rgsw[1]->GetElements()[1] += mP;

    return rgsw;
};

//
Ciphertext<DCRTPoly> ExtendedCryptoContextImpl::EvalExternalProduct(const Ciphertext<DCRTPoly>& rlwe, const std::vector<Ciphertext<DCRTPoly>>& rgsw) const 
{
    auto c = rlwe->GetElements();
    const auto d0 = Decompose(c[0]);
    const auto d1 = Decompose(c[1]);

    DCRTPoly out0(m_params->GetParamsQP(), Format::EVALUATION, true);
    DCRTPoly out1(m_params->GetParamsQP(), Format::EVALUATION, true);

    // Rad 0 (multipliseres med d0)
    out0 += (d0 * rgsw[0]->GetElements()[0]);
    out1 += (d0 * rgsw[0]->GetElements()[1]);
    out0 += (d1 * rgsw[1]->GetElements()[0]);
    out1 += (d1 * rgsw[1]->GetElements()[1]);

    auto result = rlwe->Clone();
    result->GetElements()[0] = ApproxModDown(out0);
    result->GetElements()[1] = ApproxModDown(out1);

    return result;
}

// 
std::vector<Ciphertext<DCRTPoly>> ExtendedCryptoContextImpl::EvalInternalProduct(const std::vector<Ciphertext<DCRTPoly>> &lhs, const std::vector<Ciphertext<DCRTPoly>> &rhs) const
{
    if (lhs.size() != 2 || rhs.size() != 2) {
        OPENFHE_THROW("Hybrid internal product expects 2x2 RGSW structure");
    }

    std::vector<Ciphertext<DCRTPoly>> result;
    result.reserve(2);

    for (size_t row = 0; row < 2; row++) {
        auto c = lhs[row]->GetElements();

        // Mod-down lhs row from QP to Q (drops the gadget P factor),
        // turning the row into a plain RLWE ciphertext in Q.
        DCRTPoly c0_Q = ApproxModDown(c[0]);
        DCRTPoly c1_Q = ApproxModDown(c[1]);
        c0_Q.SetFormat(Format::EVALUATION);
        c1_Q.SetFormat(Format::EVALUATION);

        auto rlwe = lhs[row]->Clone();
        rlwe->SetElements({std::move(c0_Q), std::move(c1_Q)});

        // Each row is just an external product against the rhs RGSW; reuse it
        // so noise reduction (the trailing ApproxModDown) happens once per row.
        auto ext = EvalExternalProduct(rlwe, rhs);

        // Re-power Q -> QP so the result is a valid RGSW row for chaining.
        auto& e = ext->GetElements();
        e[0].SetFormat(Format::EVALUATION);
        e[1].SetFormat(Format::EVALUATION);
        ext->SetElements({Power(e[0]), Power(e[1])});

        result.push_back(std::move(ext));
    }

    return result;
}

std::vector<Ciphertext<DCRTPoly>> ExtendedCryptoContextImpl::EvalAddRGSW(const std::vector<Ciphertext<DCRTPoly>>& lhs, const std::vector<Ciphertext<DCRTPoly>>& rhs) const 
{
    if (lhs.size() != 2 || rhs.size() != 2) {
        OPENFHE_THROW("EvalAddRGSW expects 2x2 RGSW structure");
    }

    std::vector<Ciphertext<DCRTPoly>> result;
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

std::vector<Ciphertext<DCRTPoly>> ExtendedCryptoContextImpl::EvalSubRGSW(const std::vector<Ciphertext<DCRTPoly>>& lhs, const std::vector<Ciphertext<DCRTPoly>>& rhs) const 
{
    if (lhs.size() != 2 || rhs.size() != 2) {
        OPENFHE_THROW("EvalSubRGSW expects 2x2 RGSW structure");
    }

    std::vector<Ciphertext<DCRTPoly>> result;
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

std::vector<Ciphertext<DCRTPoly>> ExtendedCryptoContextImpl::EvalMultRGSW(const std::vector<Ciphertext<DCRTPoly>>& rgsw, const Plaintext& pt) const 
{
    if (rgsw.size() != 2) {
        OPENFHE_THROW("EvalMultRGSW expects 2x2 RGSW structure");
    }

    const auto paramsQP = m_params->GetParamsQP();
    
    // 1. Extract plaintext polynomial in Q
    DCRTPoly p_Q = pt->GetElement<DCRTPoly>();
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

    DCRTPoly p_QP(p_limbs);
    
    // Switch plaintext to EVALUATION format for element-wise multiplication
    p_QP.SetFormat(Format::EVALUATION);

    // 3. Multiply every element of the RGSW matrix by the plaintext polynomial
    std::vector<Ciphertext<DCRTPoly>> result;
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

// TODO: Refactor!