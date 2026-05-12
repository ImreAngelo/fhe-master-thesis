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
    
    // Coefficient mode required?
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
    // TODO: Re-enable multi-threading
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

// TODO: Include noise
std::vector<Ciphertext<DCRTPoly>> ExtendedCryptoContextImpl::EncryptRGSW(const PublicKey<DCRTPoly>& publicKey, const Plaintext& m) const 
{
    const auto paramsQP = m_params->GetParamsQP();

    // Scale by P
    DCRTPoly mP = Power(m->GetElement<DCRTPoly>());

    std::vector<Ciphertext<DCRTPoly>> rgsw;
    for(size_t i = 0; i < 2; i++) {
        // TODO: This contains no noise!!! (not secure in production)
        DCRTPoly c0(paramsQP, Format::EVALUATION, true);
        DCRTPoly c1(paramsQP, Format::EVALUATION, true);
        
        // Keep correct CryptoContext without having a ciphertext to clone
        auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey);
        ct->SetEncodingType(m->GetEncodingType());
        ct->SetElements({c0, c1});
        rgsw.push_back(ct);
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

    c[0].SetFormat(Format::EVALUATION);
    c[1].SetFormat(Format::EVALUATION);

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

        // FIX: Modulus switch down from QP to Q FIRST!
        // This drops the factor of P that 'lhs' currently encrypts.
        DCRTPoly c0_Q = ApproxModDown(c[0]);
        DCRTPoly c1_Q = ApproxModDown(c[1]);

        c0_Q.SetFormat(Format::EVALUATION);
        c1_Q.SetFormat(Format::EVALUATION);

        // Gadget decomposition Q -> QP
        DCRTPoly d0 = Decompose(c0_Q);
        DCRTPoly d1 = Decompose(c1_Q);

        // Output row in QP
        DCRTPoly out0(m_params->GetParamsQP(), Format::EVALUATION, true);
        DCRTPoly out1(m_params->GetParamsQP(), Format::EVALUATION, true);

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

/*
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
*/

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