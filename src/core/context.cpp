#include "context.h"
#include "key/privatekey.h"
#include "schemerns/rns-cryptoparameters.h"

// TODO: Fix so macro defined in common.h is valid here
// #ifndef DEBUG_TIMING
// #define DEBUG_TIMING
// #endif

#include "utils/timer.h"

namespace Context
{
    template <typename T>
    ExtendedCryptoContextImpl<T>::ExtendedCryptoContextImpl(const CryptoContextImpl<T>& base, const CCParams<CryptoContextRGSWBGV>& params)
        : CryptoContextImpl<T>(base), m_params(params) {}

    // ----------------------------------------------------------------------
    // Helper: ApproxModDown a single QP DCRTPoly back to Q (BGV t-aware).
    // Mirrors the call at keyswitch-hybrid.cpp:389-398.
    // ----------------------------------------------------------------------
    template <typename T>
    DCRTPoly ExtendedCryptoContextImpl<T>::ApproxModDownToQ(
        const DCRTPoly& xQP,
        const std::shared_ptr<typename DCRTPoly::Params>& paramsQl
    ) const {
        const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const PlaintextModulus t = (cp->GetNoiseScale() == 1) ? 0 : cp->GetPlaintextModulus();
        return xQP.ApproxModDown(
            paramsQl, cp->GetParamsP(),
            cp->GetPInvModq(),    cp->GetPInvModqPrecon(),
            cp->GetPHatInvModp(), cp->GetPHatInvModpPrecon(),
            cp->GetPHatModq(),    cp->GetModqBarrettMu(),
            cp->GettInvModp(),    cp->GettInvModpPrecon(),
            t,                    cp->GettModqPrecon());
    }

    // ----------------------------------------------------------------------
    // Helper: lift a Q-basis ciphertext to QP basis.
    // Mirrors KeySwitchHYBRID::KeySwitchExt(addFirst=true) but casts to
    // CryptoParametersRNS instead of CryptoParametersCKKSRNS.
    // ----------------------------------------------------------------------
    template <typename T>
    std::pair<DCRTPoly, DCRTPoly> ExtendedCryptoContextImpl<T>::LiftCtxToQP(
        const Ciphertext<DCRTPoly>& ct
    ) const {
        const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const auto& cv      = ct->GetElements();
        const auto& PModq   = cp->GetPModq();
        const auto paramsP  = cp->GetParamsP();
        const auto paramsQl = cv[0].GetParams();
        const auto paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);
        const uint32_t sizeQl = paramsQl->GetParams().size();

        DCRTPoly out0(paramsQlP, Format::EVALUATION, true);
        DCRTPoly out1(paramsQlP, Format::EVALUATION, true);

        auto cMult0 = cv[0].TimesNoCheck(PModq);
        auto cMult1 = cv[1].TimesNoCheck(PModq);
        for (uint32_t i = 0; i < sizeQl; ++i) {
            out0.SetElementAtIndex(i, std::move(cMult0.GetElementAtIndex(i)));
            out1.SetElementAtIndex(i, std::move(cMult1.GetElementAtIndex(i)));
        }
        return { std::move(out0), std::move(out1) };
    }

    // ----------------------------------------------------------------------
    // External product: RLWE × RGSW → RLWE.
    //
    //   1 ModUp on each RLWE component (via EvalKeySwitchPrecomputeCore)
    // + 2 dot products in QP (top side with c1's digits, bot side with c0's digits)
    // + 2 ApproxModDown back to Ql.
    //
    // Per-level alignment is automatic: when x is mod-reduced to Ql, the
    // digit count drops from dnum to numPartQl = ceil(sizeQl/alpha), and
    // we use the standard `delta = sizeQ - sizeQl` skip pattern when
    // indexing into the full-Q RGSW (a, b) vectors.
    // ----------------------------------------------------------------------
    template <typename T>
    Ciphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalExternalProduct(
        const Ciphertext<DCRTPoly>& x,
        const RGSWCiphertext<DCRTPoly>& Y
    ) {
        DEBUG_TIMER("External Product");

        const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        if (!cp)
            throw std::runtime_error("EvalExternalProduct: cryptoparams not RNS");

        const auto& cv = x->GetElements();
        const auto paramsQl  = cv[0].GetParams();
        const auto paramsP   = cp->GetParamsP();
        const auto paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);

        const uint32_t sizeQl  = paramsQl->GetParams().size();
        const uint32_t sizeP   = paramsP->GetParams().size();
        const uint32_t sizeQlP = sizeQl + sizeP;
        const uint32_t sizeQ   = cp->GetElementParams()->GetParams().size();
        const uint32_t delta   = sizeQ - sizeQl;

        // ModUp Q→QP, returns dnum-or-numPartQl digits in QlP basis (EVAL form).
        // EvalKeySwitchPrecomputeCore handles per-level digit-count reduction.
        KeySwitchHYBRID ks;
        auto vDigits = ks.EvalKeySwitchPrecomputeCore(cv[0], cp);  // b → digits
        auto uDigits = ks.EvalKeySwitchPrecomputeCore(cv[1], cp);  // a → digits

        const uint32_t numPartQl = static_cast<uint32_t>(uDigits->size());
        if (numPartQl > Y.size())
            throw std::runtime_error("EvalExternalProduct: RGSW has fewer digits than current level requires");

        // Accumulators in QlP basis.
        DCRTPoly r0(paramsQlP, Format::EVALUATION, true);
        DCRTPoly r1(paramsQlP, Format::EVALUATION, true);

        // Inner product: result.c_k = sum_j (uDigits[j] * Y.topX_k[j] + vDigits[j] * Y.botX_k[j])
        // Y is stored at full Q (size sizeQ in Q-side, sizeP in P-side). For
        // mod-reduced x, we skip dropped towers via `delta` when indexing.
        // Mirrors keyswitch-hybrid.cpp:422-432: outer j sequential (accumulate
        // into r0/r1), inner i parallel (each thread writes a distinct tower).
        for (uint32_t j = 0; j < numPartQl; ++j) {
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
            for (uint32_t i = 0; i < sizeQlP; ++i) {
                const uint32_t idx = (i >= sizeQl) ? i + delta : i;

                const auto& uji = (*uDigits)[j].GetElementAtIndex(i);
                const auto& vji = (*vDigits)[j].GetElementAtIndex(i);

                const auto& topAji = Y.topA[j].GetElementAtIndex(idx);
                const auto& topBji = Y.topB[j].GetElementAtIndex(idx);
                const auto& botAji = Y.botA[j].GetElementAtIndex(idx);
                const auto& botBji = Y.botB[j].GetElementAtIndex(idx);

                r0.SetElementAtIndex(i, r0.GetElementAtIndex(i) + uji * topBji + vji * botBji);
                r1.SetElementAtIndex(i, r1.GetElementAtIndex(i) + uji * topAji + vji * botAji);
            }
        }

        // ApproxModDown QlP → Ql, BGV t-aware.
        auto out0 = ApproxModDownToQ(r0, paramsQl);
        auto out1 = ApproxModDownToQ(r1, paramsQl);

        auto result = x->CloneEmpty();
        result->SetElements({ std::move(out0), std::move(out1) });
        result->SetLevel(x->GetLevel());
        result->SetNoiseScaleDeg(x->GetNoiseScaleDeg());
        return result;
    }

    // ----------------------------------------------------------------------
    // Encrypt RGSW: build dnum (a, b) pairs in QP basis per side.
    //
    // Mirrors KeySwitchHYBRID::KeySwitchGenInternal(privateKey, privateKey)
    // exactly, with `m` playing the role of `sOld` for both sides:
    //   top: sOld ↦ m * s   (result row encrypts m * P * g_j * s)
    //   bot: sOld ↦ m       (result row encrypts m * P * g_j)
    // ----------------------------------------------------------------------
    template <typename T>
    RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EncryptRGSW(
        const PrivateKey<DCRTPoly>& secretKey,
        const Plaintext& plaintext
    ) {
        DEBUG_TIMER("Encrypt RGSW");

        const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        if (!cp)
            throw std::runtime_error("EncryptRGSW: cryptoparams not RNS");

        const auto paramsQ  = cp->GetElementParams();
        const auto paramsQP = cp->GetParamsQP();
        const auto& pparamsQP = paramsQP->GetParams();
        const uint32_t sizeQ  = paramsQ->GetParams().size();
        const uint32_t sizeQP = paramsQP->GetParams().size();

        const uint32_t numPerPartQ = cp->GetNumPerPartQ();
        const uint32_t numPartQ    = cp->GetNumPartQ();

        // Encode message as DCRTPoly in Q.
        // Plaintext mPlain = this->MakePackedPlaintext(msg);
        // if (!mPlain->Encode())
        //     throw std::runtime_error("EncryptRGSW: failed to encode plaintext");
        DCRTPoly mDCRT = plaintext->GetElement<DCRTPoly>();
        mDCRT.SetFormat(Format::EVALUATION);

        // Build m*s in Q (used for top rows). m is the message; s is the secret.
        const auto& sQ = secretKey->GetPrivateElement();
        DCRTPoly msQ = mDCRT * sQ;

        // Extend secret s to QP (mirrors KeySwitchGenInternal lines 61-83).
        DCRTPoly sExt(paramsQP, Format::EVALUATION, true);
        auto s0 = sQ.GetElementAtIndex(0);
        s0.SetFormat(Format::COEFFICIENT);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQP))
        for (uint32_t i = 0; i < sizeQP; ++i) {
            if (i < sizeQ) {
                auto tmp = sQ.GetElementAtIndex(i);
                tmp.SetFormat(Format::EVALUATION);
                sExt.SetElementAtIndex(i, std::move(tmp));
            } else {
                auto tmp = s0;
                tmp.SwitchModulus(pparamsQP[i]->GetModulus(), pparamsQP[i]->GetRootOfUnity(), 0, 0);
                tmp.SetFormat(Format::EVALUATION);
                sExt.SetElementAtIndex(i, std::move(tmp));
            }
        }

        const auto ns = cp->GetNoiseScale();
        const auto& PModq = cp->GetPModq();
        auto dgg = cp->GetDiscreteGaussianGenerator();
        typename DCRTPoly::DugType dug;

        RGSWCiphertext<DCRTPoly> G;
        G.topA.resize(numPartQ); G.topB.resize(numPartQ);
        G.botA.resize(numPartQ); G.botB.resize(numPartQ);

        // For each partition j, build (a, b) pair for top and bot.
        // Mirrors keyswitch-hybrid.cpp:98 — outer parallel with private RNGs.
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numPartQ)) private(dug, dgg)
        for (uint32_t part = 0; part < numPartQ; ++part) {
            const uint32_t startPartIdx = numPerPartQ * part;
            const uint32_t endPartIdx   = (sizeQ > startPartIdx + numPerPartQ) ? (startPartIdx + numPerPartQ) : sizeQ;

            // ---- top side: payload = m * s in Q-side ∩ partition_j ----
            {
                DCRTPoly a(dug, paramsQP, Format::EVALUATION);
                DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
                DCRTPoly b(paramsQP, Format::EVALUATION, true);
                for (uint32_t i = 0; i < sizeQP; ++i) {
                    const auto& ai  = a.GetElementAtIndex(i);
                    const auto& ei  = e.GetElementAtIndex(i);
                    const auto& sni = sExt.GetElementAtIndex(i);
                    if (i < startPartIdx || i >= endPartIdx) {
                        b.SetElementAtIndex(i, (-ai * sni) + (ns * ei));
                    } else {
                        const auto& msi = msQ.GetElementAtIndex(i);  // (m * s) in tower i (i < sizeQ here)
                        b.SetElementAtIndex(i, (-ai * sni) + (ns * ei) + (PModq[i] * msi));
                    }
                }
                G.topA[part] = std::move(a);
                G.topB[part] = std::move(b);
            }

            // ---- bot side: payload = m in Q-side ∩ partition_j ----
            {
                DCRTPoly a(dug, paramsQP, Format::EVALUATION);
                DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
                DCRTPoly b(paramsQP, Format::EVALUATION, true);
                for (uint32_t i = 0; i < sizeQP; ++i) {
                    const auto& ai  = a.GetElementAtIndex(i);
                    const auto& ei  = e.GetElementAtIndex(i);
                    const auto& sni = sExt.GetElementAtIndex(i);
                    if (i < startPartIdx || i >= endPartIdx) {
                        b.SetElementAtIndex(i, (-ai * sni) + (ns * ei));
                    } else {
                        const auto& mi = mDCRT.GetElementAtIndex(i);
                        b.SetElementAtIndex(i, (-ai * sni) + (ns * ei) + (PModq[i] * mi));
                    }
                }
                G.botA[part] = std::move(a);
                G.botB[part] = std::move(b);
            }
        }

        return G;
    }

    // ----------------------------------------------------------------------
    // Test/debug: decrypt one QP-basis (a, b) row by projecting back to Q
    // (ApproxModDown cancels the P factor) then doing the standard BGV
    // decryption b + a*s mod t.
    // ----------------------------------------------------------------------
    template <typename T>
    Plaintext ExtendedCryptoContextImpl<T>::DecryptRGSWRow(
        const PrivateKey<DCRTPoly>& secretKey,
        const DCRTPoly& a,
        const DCRTPoly& b
    ) {
        const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const auto paramsQ = cp->GetElementParams();

        DCRTPoly aQ = ApproxModDownToQ(a, paramsQ);
        DCRTPoly bQ = ApproxModDownToQ(b, paramsQ);

        // Construct a fresh ciphertext bound to the same CryptoContext as the
        // secret key (the Ciphertext(Key) ctor steals the context from the key).
        auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(
            std::static_pointer_cast<Key<DCRTPoly>>(secretKey));
        ct->SetElements({ std::move(bQ), std::move(aQ) });
        ct->SetEncodingType(PACKED_ENCODING);
        ct->SetLevel(0);
        ct->SetNoiseScaleDeg(1);

        Plaintext pt;
        this->Decrypt(secretKey, ct, &pt);
        return pt;
    }

    // ----------------------------------------------------------------------
    // Internal product: RGSW × RGSW → RGSW.
    //
    // For each (a, b) row of B (top and bot, dnum each):
    //   1. ApproxModDown the row from QP → Q  (cancels the gadget P factor,
    //      leaving an RLWE ciphertext that encrypts m_B · g_j  [bot]
    //      or  m_B · g_j · s  [top]).
    //   2. Run the external-product inner loop against A (ModUp Q→QP, dot
    //      product with A.top/A.bot, ApproxModDown back to Q).
    //   3. Lift back to QP via TimesNoCheck(PModq), restoring the P factor
    //      that the RGSW gadget format requires.
    //
    // This is the simple "round-trip through Q" approach: dnum × 2 outer
    // rows, each costing 2 ApproxModDowns + 2 ModUps + 1 inner-product +
    // 2 ApproxModDowns + 1 P-lift. A direct QP-only path is possible but
    // requires custom digit decomposition of QP-basis polys; not pursued.
    // ----------------------------------------------------------------------
    template <typename T>
    RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalInternalProduct(
        const RGSWCiphertext<DCRTPoly>& A,
        const RGSWCiphertext<DCRTPoly>& B
    ) {
        DEBUG_TIMER("Internal Product");

        const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        if (!cp)
            throw std::runtime_error("EvalInternalProduct: cryptoparams not RNS");
        if (A.size() != B.size())
            throw std::runtime_error("EvalInternalProduct: dnum mismatch");

        const auto paramsQ   = cp->GetElementParams();
        const auto paramsP   = cp->GetParamsP();
        const auto paramsQP  = cp->GetParamsQP();
        const uint32_t dnum  = static_cast<uint32_t>(A.size());
        const uint32_t sizeQ = paramsQ->GetParams().size();
        const uint32_t sizeP = paramsP->GetParams().size();
        const uint32_t sizeQP = sizeQ + sizeP;
        const auto& PModq = cp->GetPModq();

        KeySwitchHYBRID ks;

        // Apply the external-product action of A to a single QP-basis row of
        // B, returning the resulting QP-basis (a', b') with the gadget P
        // factor restored.
        auto applyAToRow = [&](const DCRTPoly& aQP, const DCRTPoly& bQP) {
            // (1) Project from QP → Q, cancelling the gadget P factor.
            DCRTPoly aQ = ApproxModDownToQ(aQP, paramsQ);
            DCRTPoly bQ = ApproxModDownToQ(bQP, paramsQ);

            // (2) External product against A (ModUp Q→QP, dot product, ApproxModDown).
            auto uDig = ks.EvalKeySwitchPrecomputeCore(aQ, cp);
            auto vDig = ks.EvalKeySwitchPrecomputeCore(bQ, cp);

            DCRTPoly r0(paramsQP, Format::EVALUATION, true);
            DCRTPoly r1(paramsQP, Format::EVALUATION, true);
            for (uint32_t j = 0; j < dnum; ++j) {
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQP))
                for (uint32_t i = 0; i < sizeQP; ++i) {
                    const auto& uji = (*uDig)[j].GetElementAtIndex(i);
                    const auto& vji = (*vDig)[j].GetElementAtIndex(i);

                    r0.SetElementAtIndex(i, r0.GetElementAtIndex(i)
                        + uji * A.topB[j].GetElementAtIndex(i)
                        + vji * A.botB[j].GetElementAtIndex(i));
                    r1.SetElementAtIndex(i, r1.GetElementAtIndex(i)
                        + uji * A.topA[j].GetElementAtIndex(i)
                        + vji * A.botA[j].GetElementAtIndex(i));
                }
            }

            DCRTPoly out0Q = ApproxModDownToQ(r0, paramsQ);
            DCRTPoly out1Q = ApproxModDownToQ(r1, paramsQ);

            // (3) Lift back to QP with the P factor on Q-side, zeros on P-side.
            auto mult0 = out0Q.TimesNoCheck(PModq);
            auto mult1 = out1Q.TimesNoCheck(PModq);
            DCRTPoly outB(paramsQP, Format::EVALUATION, true);
            DCRTPoly outA(paramsQP, Format::EVALUATION, true);
            for (uint32_t i = 0; i < sizeQ; ++i) {
                outB.SetElementAtIndex(i, std::move(mult0.GetElementAtIndex(i)));
                outA.SetElementAtIndex(i, std::move(mult1.GetElementAtIndex(i)));
            }
            return std::pair<DCRTPoly, DCRTPoly>{ std::move(outA), std::move(outB) };
        };

        RGSWCiphertext<DCRTPoly> C;
        C.topA.resize(dnum); C.topB.resize(dnum);
        C.botA.resize(dnum); C.botB.resize(dnum);
        for (uint32_t j = 0; j < dnum; ++j) {
            auto top = applyAToRow(B.topA[j], B.topB[j]);
            auto bot = applyAToRow(B.botA[j], B.botB[j]);
            C.topA[j] = std::move(top.first);
            C.topB[j] = std::move(top.second);
            C.botA[j] = std::move(bot.first);
            C.botB[j] = std::move(bot.second);
        }
        return C;
    }

    template <typename T>
    RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalAddRGSW(
        const RGSWCiphertext<DCRTPoly>& A,
        const RGSWCiphertext<DCRTPoly>& B
    ) {
        if (A.size() != B.size())
            throw std::runtime_error("EvalAddRGSW: dnum mismatch");
        RGSWCiphertext<DCRTPoly> R;
        const size_t d = A.size();
        R.topA.resize(d); R.topB.resize(d); R.botA.resize(d); R.botB.resize(d);
        for (size_t j = 0; j < d; ++j) {
            R.topA[j] = A.topA[j] + B.topA[j];
            R.topB[j] = A.topB[j] + B.topB[j];
            R.botA[j] = A.botA[j] + B.botA[j];
            R.botB[j] = A.botB[j] + B.botB[j];
        }
        return R;
    }

    template <typename T>
    RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalSubRGSW(
        const RGSWCiphertext<DCRTPoly>& A,
        const RGSWCiphertext<DCRTPoly>& B
    ) {
        if (A.size() != B.size())
            throw std::runtime_error("EvalSubRGSW: dnum mismatch");
        RGSWCiphertext<DCRTPoly> R;
        const size_t d = A.size();
        R.topA.resize(d); R.topB.resize(d); R.botA.resize(d); R.botB.resize(d);
        for (size_t j = 0; j < d; ++j) {
            R.topA[j] = A.topA[j] - B.topA[j];
            R.topB[j] = A.topB[j] - B.topB[j];
            R.botA[j] = A.botA[j] - B.botA[j];
            R.botB[j] = A.botB[j] - B.botB[j];
        }
        return R;
    }

    // ----------------------------------------------------------------------
    // Plaintext × RGSW: scale every QP-basis (a, b) row by the plaintext.
    //
    // Encode the plaintext to its Q-basis DCRTPoly, lift to QP (Q-side as is,
    // P-side via SwitchModulus on each P-tower — same pattern used to extend
    // the secret key in EncryptRGSW), then element-wise multiply each of
    // topA/topB/botA/botB by the lifted polynomial. Linearity preserves the
    // RGSW gadget structure: row j now encrypts (m · p) · P · g_j.
    // ----------------------------------------------------------------------
    template <typename T>
    RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalMultPlain(
        const Plaintext& p,
        const RGSWCiphertext<DCRTPoly>& A
    ) {
        DEBUG_TIMER("EvalMultPlain RGSW");

        const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        if (!cp)
            throw std::runtime_error("EvalMultPlain: cryptoparams not RNS");

        const auto paramsQ    = cp->GetElementParams();
        const auto paramsQP   = cp->GetParamsQP();
        const auto& pparamsQP = paramsQP->GetParams();
        const uint32_t sizeQ  = paramsQ->GetParams().size();
        const uint32_t sizeQP = paramsQP->GetParams().size();

        if (!p->Encode())
            throw std::runtime_error("EvalMultPlain: failed to encode plaintext");
        DCRTPoly pQ = p->GetElement<DCRTPoly>();
        pQ.SetFormat(Format::EVALUATION);

        DCRTPoly pQP(paramsQP, Format::EVALUATION, true);
        for (uint32_t i = 0; i < sizeQ; ++i) {
            pQP.SetElementAtIndex(i, pQ.GetElementAtIndex(i));
        }
        auto p0 = pQ.GetElementAtIndex(0);
        p0.SetFormat(Format::COEFFICIENT);
        for (uint32_t i = sizeQ; i < sizeQP; ++i) {
            auto tmp = p0;
            tmp.SwitchModulus(pparamsQP[i]->GetModulus(), pparamsQP[i]->GetRootOfUnity(), 0, 0);
            tmp.SetFormat(Format::EVALUATION);
            pQP.SetElementAtIndex(i, std::move(tmp));
        }

        const size_t dnum = A.size();
        RGSWCiphertext<DCRTPoly> R;
        R.topA.resize(dnum); R.topB.resize(dnum);
        R.botA.resize(dnum); R.botB.resize(dnum);
        for (size_t j = 0; j < dnum; ++j) {
            R.topA[j] = A.topA[j] * pQP;
            R.topB[j] = A.topB[j] * pQP;
            R.botA[j] = A.botA[j] * pQP;
            R.botB[j] = A.botB[j] * pQP;
        }
        return R;
    }

    template <typename T>
    std::vector<Ciphertext<T>> ExtendedCryptoContextImpl<T>::ExpandRLWEHoisted(
        const Ciphertext<T>& ciphertext,
        const PublicKey<T>& publicKey,
        const uint32_t len
    ) {
        const auto ciphertext_n = this->Encrypt(publicKey, this->MakePackedPlaintext({ 1 }));

        std::vector<Ciphertext<T>> c(len);
        c[0] = this->EvalMult(ciphertext, ciphertext_n);

        const auto precomputed = this->EvalFastRotationPrecompute(ciphertext);
        for (uint32_t i = 1; i < len; i++) {
            const auto rotated = this->EvalFastRotation(ciphertext, i, precomputed);
            c[i] = this->EvalMult(rotated, ciphertext_n);
        }

        return c;
    }

    template class ExtendedCryptoContextImpl<DCRTPoly>;
}
