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

    DEBUG_PRINT("Created ExtendedCryptoContext with #Q = " << numQ << ", #P = " << numP);

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
std::vector<Ciphertext<DCRTPoly>> ExtendedCryptoContextImpl::EncryptRGSW(const PrivateKey<DCRTPoly>& sk, const Plaintext& pt) const
{
    const auto paramsQP = m_params->GetParamsQP();
    const auto t = m_params->GetPlaintextModulus();
    
    // 1. Properly lift the Secret Key from Q to QP 
    // Bypass CRT: Extract just the first limb of Q. Because 's' is bounded by {-1, 0, 1}, 
    // this limb contains the exact small integer values we need.
    DCRTPoly s_Q = sk->GetPrivateElement();
    s_Q.SetFormat(Format::COEFFICIENT);
    
    NativePoly s_first = s_Q.GetElementAtIndex(0);
    NativeInteger q0 = s_Q.GetParams()->GetParams()[0]->GetModulus();
    uint64_t q0_int = q0.ConvertToInt();
    uint64_t q0_half = q0_int >> 1;
    uint32_t ringDim = s_first.GetLength();

    std::vector<NativePoly> s_limbs;
    for (size_t j = 0; j < paramsQP->GetParams().size(); j++) {
        auto limbParams = paramsQP->GetParams()[j];
        NativeInteger pj = limbParams->GetModulus();
        uint64_t pj_int = pj.ConvertToInt();
        NativePoly limb(limbParams, Format::COEFFICIENT, true);
        
        for (size_t i = 0; i < ringDim; i++) {
            uint64_t val_int = s_first[i].ConvertToInt();
            if (val_int > q0_half) {
                // Number is negative. Diff gives us the absolute value (e.g., 1 for -1)
                uint64_t diff = q0_int - val_int;
                // Safely map it to the new limb modulus (pj - 1)
                limb[i] = NativeInteger(pj_int - diff);
            } else {
                // Number is positive
                limb[i] = NativeInteger(val_int);
            }
        }
        s_limbs.push_back(std::move(limb));
    }
    
    DCRTPoly s_QP(s_limbs);
    s_QP.SetFormat(Format::EVALUATION);

    // 2. Setup Generators for a (Uniform) and e (Gaussian)
    const auto& dgg = m_params->GetDiscreteGaussianGenerator();
    DCRTPoly::DugType dug; 

    std::vector<Ciphertext<DCRTPoly>> rgsw;
    rgsw.reserve(2);

    for (size_t row = 0; row < 2; row++) {
        DCRTPoly a(dug, paramsQP, Format::EVALUATION);
        DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
        
        // c1 = a, c0 = -(a*s + t*e) mod QP
        DCRTPoly c1 = a;
        DCRTPoly c0 = a * s_QP;
        
        e = e * t; 
        c0 += e;
        c0 = c0.Negate(); 

        auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(sk);
        ct->SetElements({std::move(c0), std::move(c1)});
        rgsw.push_back(std::move(ct));
    }

    // 3. Add m * P to the diagonal
    BigInteger P_mod = m_params->GetParamsP()->GetModulus();
    
    DCRTPoly m_Q = pt->GetElement<DCRTPoly>();
    m_Q.SetFormat(Format::COEFFICIENT);
    
    // Bypass CRT for the message as well
    NativePoly m_first = m_Q.GetElementAtIndex(0);

    std::vector<NativePoly> m_limbs;
    for (size_t j = 0; j < paramsQP->GetParams().size(); j++) {
        auto limbParams = paramsQP->GetParams()[j];
        NativeInteger pj = limbParams->GetModulus();
        NativePoly limb(limbParams, Format::COEFFICIENT, true);
        
        // Compute P_mod % pj
        BigInteger pj_BI(pj.ConvertToInt());
        NativeInteger P_mod_pj(P_mod.Mod(pj_BI).ConvertToInt());
        
        for (size_t i = 0; i < ringDim; i++) {
            NativeInteger val = m_first[i]; // Plaintext message is safely within [0, t-1]
            limb[i] = val.ModMul(P_mod_pj, pj);
        }
        m_limbs.push_back(std::move(limb));
    }

    DCRTPoly mP(m_limbs);
    mP.SetFormat(Format::EVALUATION);

    // Safely retrieve, modify, and set the elements to avoid const reference errors
    std::vector<DCRTPoly> row0 = rgsw[0]->GetElements();
    std::vector<DCRTPoly> row1 = rgsw[1]->GetElements();
    row0[0] += mP;
    row1[1] += mP;
    rgsw[0]->SetElements(std::move(row0));
    rgsw[1]->SetElements(std::move(row1));

    return rgsw;
}

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
        auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>();
        ct->SetElements({std::move(out0), std::move(out1)});

        result.push_back(std::move(ct));
    }

    return result;
}

// TODO: Refactor!