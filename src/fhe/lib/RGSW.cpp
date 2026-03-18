#include "fhe/include/RGSW.h"

namespace fhe {

using namespace lbcrypto;

// ─────────────────────────────────────────────────────────────────────────────
// HomExpand
// ─────────────────────────────────────────────────────────────────────────────

RGSWCiphertext HomExpand(const CryptoContext<DCRTPoly>& cc,
                         const Ciphertext<DCRTPoly>&    ct,
                         const PrivateKey<DCRTPoly>&    sk)
{
    // Crypto parameters (digit size, noise scale, Gaussian generator)
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const uint32_t digitSize = cryptoParams->GetDigitSize();
    const auto     ns        = cryptoParams->GetNoiseScale();
    auto           dgg       = cryptoParams->GetDiscreteGaussianGenerator();
    DCRTPoly::DugType dug;

    // ── Recover the plaintext scalar and build the RGSW message ─────────────
    //
    // We need the *unscaled* plaintext polynomial as the RGSW message.
    // Using Plaintext::GetElement<DCRTPoly>() would give the polynomial
    // multiplied by BGV's internal scalingFactorInt, making the external
    // product multiply by that factor instead of by the plaintext value.
    //
    // For scalar messages (bits), the fix is to construct the constant
    // polynomial `bit` directly in COEFFICIENT format [bit, 0, 0, …],
    // then NTT-convert to EVALUATION.  This bypasses the encoding scaling.

    Plaintext pt;
    cc->Decrypt(sk, ct, &pt);
    pt->SetLength(1);
    int64_t bit = pt->GetPackedValue()[0];

    const auto& ep = ct->GetElements()[0].GetParams();

    DCRTPoly mPoly(ep, Format::COEFFICIENT, true);   // zero polynomial
    if (bit != 0) {
        for (uint32_t i = 0; i < mPoly.GetNumOfElements(); ++i) {
            NativePoly elem(mPoly.GetElementAtIndex(i));  // copy
            elem[0] = NativeInteger(static_cast<uint64_t>(bit));
            mPoly.SetElementAtIndex(i, std::move(elem));
        }
    }
    mPoly.SetFormat(Format::EVALUATION);             // forward NTT

    // ── Secret key restricted to ciphertext level ────────────────────────────
    DCRTPoly s = sk->GetPrivateElement();
    s.SetFormat(Format::EVALUATION);
    {
        const uint32_t ctLimbs = static_cast<uint32_t>(ep->GetParams().size());
        const uint32_t skLimbs = s.GetNumOfElements();
        if (skLimbs > ctLimbs)
            s.DropLastElements(skLimbs - ctLimbs);
    }

    // m·s: for bit ∈ {0,1} this is either 0 or s itself
    DCRTPoly msPoly = mPoly * s;

    // ── Compute window (digit) layout — identical to KeySwitchBV::KeySwitchGenInternal ─

    const uint32_t numLimbs = mPoly.GetNumOfElements();
    std::vector<uint32_t> arrWindows(numLimbs);
    uint32_t nWindows = 0;

    if (digitSize > 0) {
        for (uint32_t i = 0; i < numLimbs; ++i) {
            arrWindows[i] = nWindows;
            nWindows += static_cast<uint32_t>(
                std::ceil(static_cast<double>(
                    mPoly.GetElementAtIndex(i).GetModulus().GetMSB()) / digitSize));
        }
    } else {
        nWindows = numLimbs;
        for (uint32_t i = 0; i < numLimbs; ++i)
            arrWindows[i] = i;
    }

    // ── Allocate RGSW storage ────────────────────────────────────────────────

    RGSWCiphertext rgsw;
    rgsw.digitSize = digitSize;
    rgsw.b0.resize(nWindows);  rgsw.a0.resize(nWindows);
    rgsw.b1.resize(nWindows);  rgsw.a1.resize(nWindows);

    // Helper: fresh RLWE encryption of a single-limb message.
    //
    //   Sets the 'limb'-th CRT component of bv[j] to msgLimb, everything else
    //   to zero, then subtracts av[j]·s + noise to produce
    //       bv[j] + av[j]·s ≈ msgLimb  (in the 'limb'-th CRT position).
    //
    // This is the same construction used in KeySwitchBV for relinearisation keys.
    auto freshRLWE = [&](std::vector<DCRTPoly>& bv, std::vector<DCRTPoly>& av,
                         uint32_t j, uint32_t limb,
                         const DCRTPoly::PolyType& msgLimb)
    {
        av[j] = DCRTPoly(dug, ep, Format::EVALUATION);
        bv[j] = DCRTPoly(ep, Format::EVALUATION, true);  // zero polynomial
        bv[j].SetElementAtIndex(limb, msgLimb);
        bv[j] -= av[j] * s + DCRTPoly(dgg, ep, Format::EVALUATION) * ns;
    };

    // ── Generate RGSW rows ───────────────────────────────────────────────────

    if (digitSize > 0) {
        // With digit decomposition: each CRT limb is split into several digits.
        // PowersOfBase(digitSize) gives { msg, msg·B, msg·B², … } for one limb.
        for (uint32_t i = 0; i < numLimbs; ++i) {
            auto mDecomposed  = mPoly.GetElementAtIndex(i).PowersOfBase(digitSize);
            auto msDecomposed = msPoly.GetElementAtIndex(i).PowersOfBase(digitSize);
            for (uint32_t j = arrWindows[i], k = 0; k < mDecomposed.size(); ++j, ++k) {
                freshRLWE(rgsw.b0, rgsw.a0, j, i, mDecomposed[k]);   // RLWE(m·g_j)
                freshRLWE(rgsw.b1, rgsw.a1, j, i, msDecomposed[k]);  // RLWE(m·s·g_j)
            }
        }
    } else {
        // Without digit decomposition: one gadget element per CRT limb.
        // Gadget element g_i ≡ "the i-th CRT basis projection".
        for (uint32_t i = 0; i < numLimbs; ++i) {
            freshRLWE(rgsw.b0, rgsw.a0, i, i, mPoly.GetElementAtIndex(i));   // RLWE(m·g_i)
            freshRLWE(rgsw.b1, rgsw.a1, i, i, msPoly.GetElementAtIndex(i));  // RLWE(m·s·g_i)
        }
    }

    return rgsw;
}

// ─────────────────────────────────────────────────────────────────────────────
// EvalExternalProduct
// ─────────────────────────────────────────────────────────────────────────────

Ciphertext<DCRTPoly> EvalExternalProduct(const CryptoContext<DCRTPoly>& cc,
                                         const RGSWCiphertext&          rgsw,
                                         const Ciphertext<DCRTPoly>&    ct)
{
    // Digit-decompose both ciphertext components.
    // CRTDecompose returns EVALUATION-format DCRTPolys, one per gadget window,
    // matching the layout used when building the RGSW rows in HomExpand.
    const auto digits0 = ct->GetElements()[0].CRTDecompose(rgsw.digitSize);
    const auto digits1 = ct->GetElements()[1].CRTDecompose(rgsw.digitSize);

    const uint32_t l = static_cast<uint32_t>(rgsw.b0.size());

    // If the RGSW was created at a higher level than ct (more CRT limbs),
    // drop the extra limbs — identical to EvalFastKeySwitchCore in BV.
    const uint32_t rgswLimbs = rgsw.b0[0].GetParams()->GetParams().size();
    const uint32_t ctLimbs   = ct->GetElements()[0].GetParams()->GetParams().size();
    const uint32_t diffQl    = (rgswLimbs > ctLimbs) ? (rgswLimbs - ctLimbs) : 0;

    std::vector<DCRTPoly> b0v(rgsw.b0), a0v(rgsw.a0);
    std::vector<DCRTPoly> b1v(rgsw.b1), a1v(rgsw.a1);
    if (diffQl > 0) {
        for (uint32_t i = 0; i < l; ++i) {
            b0v[i].DropLastElements(diffQl);  a0v[i].DropLastElements(diffQl);
            b1v[i].DropLastElements(diffQl);  a1v[i].DropLastElements(diffQl);
        }
    }

    // Accumulate:
    //   result_b = Σ_i  digits0[i]·b0[i]  +  digits1[i]·b1[i]
    //   result_a = Σ_i  digits0[i]·a0[i]  +  digits1[i]·a1[i]
    //
    // Correctness (j-th CRT component):
    //   result_b_j + result_a_j · s_j
    //     = Σ_i (d0_i_j · m_j·g_{i,j}  +  d1_i_j · (m·s)_j·g_{i,j})  + noise
    //     = m_j · (Σ_i d0_i_j·g_{i,j}  +  s_j · Σ_i d1_i_j·g_{i,j}) + noise
    //     ≈ m_j · (c0_j + s_j·c1_j)   =  m_j · v_j

    DCRTPoly result_b = digits0[0] * b0v[0] + digits1[0] * b1v[0];
    DCRTPoly result_a = digits0[0] * a0v[0] + digits1[0] * a1v[0];
    for (uint32_t i = 1; i < l; ++i) {
        result_b += digits0[i] * b0v[i] + digits1[i] * b1v[i];
        result_a += digits0[i] * a0v[i] + digits1[i] * a1v[i];
    }

    // Clone ct to inherit its CryptoObject header (context, key tag, encoding type,
    // level, noise scale degree), then overwrite the ring elements.
    // Constructing from cc alone leaves the key tag empty, causing TypeCheck failures
    // in subsequent operations like EvalSub.
    auto result = std::make_shared<CiphertextImpl<DCRTPoly>>(ct);
    result->SetElements({std::move(result_b), std::move(result_a)});
    return result;
}

} // namespace fhe
