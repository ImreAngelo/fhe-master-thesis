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

// Exact mod down QP -> Q (Centered Scale-and-Round)
// Eliminates approximation errors and DC-bias offsets.
DCRTPoly ExtendedCryptoContextImpl::ExactModDown(const DCRTPoly& input) const 
{
    const auto paramsQ = m_params->GetElementParams()->GetParams();
    const auto paramsP = m_params->GetParamsP()->GetParams();
    
    uint32_t numQ = paramsQ.size();
    uint32_t numP = paramsP.size();
    uint32_t n = m_params->GetElementParams()->GetRingDimension();

    // 1. Base extension requires coefficient format
    DCRTPoly inputCoeff = input;
    inputCoeff.SetFormat(Format::COEFFICIENT);
    const auto& in_limbs = inputCoeff.GetAllElements();

    DCRTPoly result(m_params->GetElementParams(), Format::COEFFICIENT, true);
    auto& res_limbs = result.GetAllElements();

    // ====================================================================
    // PRECOMPUTATIONS: 
    // (Move these to the constructor for production performance)
    // ====================================================================
    BigInteger P(1);
    for (uint32_t j = 0; j < numP; j++) {
        P = P * BigInteger(paramsP[j]->GetModulus());
    }

    // BGV plaintext-modulus correction. Subtracting the bare centered remainder
    // [V]_P would leave a non-multiple-of-t perturbation that corrupts the
    // message mod t. Instead we subtract t * [V * t^{-1}]_P (still == V mod P,
    // but == 0 mod t), exactly mirroring OpenFHE's ApproxModDown t^{-1}/t trick.
    // noiseScale == 1 means no plaintext modulus (e.g. CKKS): skip the rescale.
    const NativeInteger t = (m_params->GetNoiseScale() == 1)
        ? NativeInteger(0)
        : NativeInteger(m_params->GetPlaintextModulus());
    const bool applyTCorrection = (t > NativeInteger(0));

    std::vector<NativeInteger> P_j_inv_mod_p(numP);
    std::vector<double> p_j_double(numP);

    for (uint32_t j = 0; j < numP; j++) {
        const auto& pj = paramsP[j]->GetModulus();
        BigInteger P_j = P / BigInteger(pj);
        NativeInteger inv = P_j.ModInverse(pj).ConvertToInt();
        // Fold t^{-1} mod p_j into the (P/p_j)^{-1} factor so the reconstructed
        // centered value below is [V * t^{-1}]_P rather than [V]_P.
        if (applyTCorrection)
            inv = inv.ModMul(t.ModInverse(pj), pj);
        P_j_inv_mod_p[j] = inv;
        p_j_double[j] = pj.ConvertToDouble();
    }

    std::vector<NativeInteger> P_inv_mod_q(numQ), P_mod_q(numQ);
    std::vector<std::vector<NativeInteger>> P_j_mod_q(numP, std::vector<NativeInteger>(numQ));

    for (uint32_t i = 0; i < numQ; i++) {
        const auto& qi = paramsQ[i]->GetModulus();
        P_inv_mod_q[i] = P.ModInverse(qi).ConvertToInt();
        P_mod_q[i] = P.Mod(qi).ConvertToInt();

        for (uint32_t j = 0; j < numP; j++) {
            BigInteger P_j = P / BigInteger(paramsP[j]->GetModulus());
            P_j_mod_q[j][i] = P_j.Mod(qi).ConvertToInt();
        }
    }
    // ====================================================================

    // 2. Process P-limbs: y_j = x_j * (P/p_j)^{-1} mod p_j (No Phalf addition!)
    std::vector<NativePoly> y(numP);
    for (uint32_t j = 0; j < numP; j++) {
        y[j] = NativePoly(paramsP[j], Format::COEFFICIENT, true);
        const auto& pj = paramsP[j]->GetModulus();
        
        for (uint32_t col = 0; col < n; col++) {
            NativeInteger val = in_limbs[numQ + j][col]; 
            y[j][col] = val.ModMul(P_j_inv_mod_p[j], pj);
        }
    }

    // 3. Exact Base Extension (P -> Q) and Centered Scale-Down
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numQ))
    for (uint32_t i = 0; i < numQ; i++) {
        const auto& qi = paramsQ[i]->GetModulus();
        auto& out_poly = res_limbs[i];

        for (uint32_t col = 0; col < n; col++) {
            // A. Compute the fractional alpha to track integer overflow
            double alpha_double = 0.0;
            for (uint32_t j = 0; j < numP; j++) {
                alpha_double += y[j][col].ConvertToDouble() / p_j_double[j];
            }
            // std::round correctly resolves the centered remainder
            NativeInteger alpha = static_cast<uint64_t>(std::round(alpha_double));

            // B. Reconstruct the centered remainder X in the q_i basis
            NativeInteger X = 0;
            for (uint32_t j = 0; j < numP; j++) {
                NativeInteger term = y[j][col].ModMul(P_j_mod_q[j][i], qi);
                X = X.ModAdd(term, qi);
            }
            NativeInteger alpha_P = alpha.ModMul(P_mod_q[i], qi);
            X = X.ModSub(alpha_P, qi); // X == [V * t^{-1}]_P, centered in [-P/2, P/2)

            // Re-apply the plaintext modulus: t * [V * t^{-1}]_P == V mod P,
            // but == 0 mod t, so the dropped remainder no longer corrupts the
            // BGV message. (No-op when applyTCorrection is false.)
            if (applyTCorrection)
                X = X.ModMul(t.Mod(qi), qi);

            // C. Subtract centered remainder to make division exact
            NativeInteger xi = in_limbs[i][col]; // No Phalf addition!
            xi = xi.ModSub(X, qi);               // Subtract centered remainder

            // Multiply by P^{-1}
            out_poly[col] = xi.ModMul(P_inv_mod_q[i], qi);
        }
    }

    // 4. Return to EVALUATION format for standard RLWE chaining
    result.SetFormat(Format::EVALUATION);
    return result;
}

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

std::vector<DCRTPoly> ExtendedCryptoContextImpl::EncryptZeroQ(const PrivateKey<DCRTPoly>& secretKey) const
{
    const auto paramsQ = m_params->GetElementParams();
    const auto ns = m_params->GetNoiseScale();
    const DCRTPoly& s = secretKey->GetPrivateElement();

    typename DCRTPoly::DugType dug;
    const auto& dgg = m_params->GetDiscreteGaussianGenerator();

    DCRTPoly a(dug, paramsQ, Format::EVALUATION);
    DCRTPoly e(dgg, paramsQ, Format::EVALUATION);

    // BGV-style zero encryption: c0 = a*s + ns*e, c1 = -a  =>  c0 + c1*s = ns*e
    DCRTPoly c0 = a * s + e * NativeInteger(ns);
    DCRTPoly c1 = a.Negate();

    return {std::move(c0), std::move(c1)};
}

// m * g_i, where g_i = qHat_i * [qHat_i^{-1}]_{q_i} is the RNS-CRT gadget component.
// Since g_i == 1 (mod q_i) and == 0 (mod q_k != i), the product is just m kept in
// limb i and zeroed everywhere else.
DCRTPoly ExtendedCryptoContextImpl::MaskToLimb(const DCRTPoly& m, uint32_t i) const
{
    const auto paramsQ = m_params->GetElementParams();
    DCRTPoly r(paramsQ, Format::EVALUATION, true); // all-zero

    DCRTPoly mm = m;
    mm.SetFormat(Format::EVALUATION);
    r.SetElementAtIndex(i, mm.GetElementAtIndex(i));
    return r;
}

// g^{-1}(x): L digits with digit_i == [x]_{q_i} (x's residue mod q_i, in [0, q_i))
// lifted into every Q-limb. Then sum_i digit_i * (m * g_i) == x * m (mod Q), because
// digit_i * MaskToLimb(m, i) is nonzero only in limb i and equals (x*m mod q_i) there.
std::vector<DCRTPoly> ExtendedCryptoContextImpl::DigitDecompose(const DCRTPoly& x) const
{
    const auto paramsQ = m_params->GetElementParams();
    const auto& limbParams = paramsQ->GetParams();
    const uint32_t L = limbParams.size();
    const uint32_t n = m_params->GetElementParams()->GetRingDimension();

    DCRTPoly xc = x;
    xc.SetFormat(Format::COEFFICIENT);

    std::vector<DCRTPoly> digits;
    digits.reserve(L);

    for (uint32_t i = 0; i < L; i++) {
        const auto& vi = xc.GetElementAtIndex(i); // residues mod q_i, in [0, q_i)

        DCRTPoly d(paramsQ, Format::COEFFICIENT, true);
        auto& dl = d.GetAllElements();
        for (uint32_t k = 0; k < L; k++) {
            const auto qk = limbParams[k]->GetModulus();
            for (uint32_t col = 0; col < n; col++) {
                dl[k][col] = vi[col].Mod(qk);
            }
        }
        d.SetFormat(Format::EVALUATION);
        digits.push_back(std::move(d));
    }
    return digits;
}

// RGSW(m) = Z + m*G with the RNS-CRT gadget G. 2L rows of Q-resident RLWE:
//   row i      (0 <= i < L) = (z0 + m*g_i, z1)        -- pairs with g^{-1}(c0)
//   row L+i    (0 <= i < L) = (z0, z1 + m*g_i)        -- pairs with g^{-1}(c1)
std::vector<Ciphertext<DCRTPoly>> ExtendedCryptoContextImpl::EncryptRGSW(const PrivateKey<DCRTPoly>& secretKey, const Plaintext& m) const
{
    DCRTPoly mElem = m->GetElement<DCRTPoly>();
    mElem.SetFormat(Format::EVALUATION);

    const uint32_t L = m_params->GetElementParams()->GetParams().size();

    std::vector<Ciphertext<DCRTPoly>> rgsw;
    rgsw.reserve(2 * L);

    for (uint32_t slot = 0; slot < 2; slot++) {
        for (uint32_t i = 0; i < L; i++) {
            auto z = EncryptZeroQ(secretKey);
            DCRTPoly mg = MaskToLimb(mElem, i);

            auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(secretKey);
            ct->SetEncodingType(m->GetEncodingType());
            if (slot == 0)
                ct->SetElements({z[0] + mg, std::move(z[1])});
            else
                ct->SetElements({std::move(z[0]), z[1] + mg});
            rgsw.push_back(std::move(ct));
        }
    }

    return rgsw;
};

//
Ciphertext<DCRTPoly> ExtendedCryptoContextImpl::EvalExternalProduct(const Ciphertext<DCRTPoly>& rlwe, const std::vector<Ciphertext<DCRTPoly>>& rgsw) const 
{
    const uint32_t L = m_params->GetElementParams()->GetParams().size();
    if (rgsw.size() != 2 * L) {
        OPENFHE_THROW("EvalExternalProduct expects a 2L-row RGSW");
    }

    auto c = rlwe->GetElements();
    const auto d0 = DigitDecompose(c[0]); // L digits of c0
    const auto d1 = DigitDecompose(c[1]); // L digits of c1

    const auto paramsQ = m_params->GetElementParams();
    DCRTPoly out0(paramsQ, Format::EVALUATION, true);
    DCRTPoly out1(paramsQ, Format::EVALUATION, true);

    // sum_i g^{-1}(c0)_i * row_i  +  sum_i g^{-1}(c1)_i * row_{L+i}
    for (uint32_t i = 0; i < L; i++) {
        out0 += d0[i] * rgsw[i]->GetElements()[0];
        out1 += d0[i] * rgsw[i]->GetElements()[1];
        out0 += d1[i] * rgsw[L + i]->GetElements()[0];
        out1 += d1[i] * rgsw[L + i]->GetElements()[1];
    }

    auto result = rlwe->Clone();
    result->SetElements({std::move(out0), std::move(out1)});
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

        // 1. Mod-down lhs row from QP to Q
        DCRTPoly c0_Q = ExactModDown(c[0]);
        DCRTPoly c1_Q = ExactModDown(c[1]);
        c0_Q.SetFormat(Format::EVALUATION);
        c1_Q.SetFormat(Format::EVALUATION);

        // 2. Decompose the Q-elements into QP
        const auto d0 = Decompose(c0_Q);
        const auto d1 = Decompose(c1_Q);

        // 3. Accumulate the product directly in QP
        DCRTPoly out0(m_params->GetParamsQP(), Format::EVALUATION, true);
        DCRTPoly out1(m_params->GetParamsQP(), Format::EVALUATION, true);

        out0 += (d0 * rhs[0]->GetElements()[0]);
        out1 += (d0 * rhs[0]->GetElements()[1]);
        out0 += (d1 * rhs[1]->GetElements()[0]);
        out1 += (d1 * rhs[1]->GetElements()[1]);

        // 4. Do NOT ApproxModDown or Power here. The row is exactly where it needs to be.
        auto out_row = lhs[row]->Clone();
        out_row->SetElements({std::move(out0), std::move(out1)});
        result.push_back(std::move(out_row));
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