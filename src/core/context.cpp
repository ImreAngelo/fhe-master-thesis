#include "context.h"
#include "key/privatekey.h"
#include "schemerns/rns-cryptoparameters.h"

// TODO: Fix so macro defined in common.h is valid here
#ifndef DEBUG_TIMING
#define DEBUG_TIMING
#endif

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
    // External product: RLWE × RGSW → RLWE.
    //
    //   1 ModUp on each RLWE component (via EvalKeySwitchPrecomputeCore)
    // + 2 EvalFastKeySwitchCoreExt calls (one per RGSW side, dot product in QlP)
    // + tower-wise add of the two QlP results
    // + 2 ApproxModDown back to Ql (via the BGV-t-aware helper).
    //
    // Per-level alignment is automatic: EvalFastKeySwitchCoreExt uses the
    // `delta = sizeQ - sizeQl` skip pattern when indexing into the full-Q
    // EvalKey, so mod-reduced x against full-Q Y just works.
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
        if (!Y.top || !Y.bot)
            throw std::runtime_error("EvalExternalProduct: RGSW operand has null top/bot key");

        const auto& cv = x->GetElements();
        const auto paramsQl = cv[0].GetParams();

        KeySwitchHYBRID ks;
        auto vDigits = ks.EvalKeySwitchPrecomputeCore(cv[0], cp);  // b → digits
        auto uDigits = ks.EvalKeySwitchPrecomputeCore(cv[1], cp);  // a → digits

        if (uDigits->size() > Y.size())
            throw std::runtime_error("EvalExternalProduct: RGSW has fewer digits than current level requires");

        // Two dot products in QlP via OpenFHE's primitive (delta-skip + OMP).
        auto topRes = ks.EvalFastKeySwitchCoreExt(uDigits, Y.top, paramsQl);
        auto botRes = ks.EvalFastKeySwitchCoreExt(vDigits, Y.bot, paramsQl);

        // Sum the two sides in QlP, then a single shared ApproxModDown per slot.
        DCRTPoly r0 = (*topRes)[0] + (*botRes)[0];
        DCRTPoly r1 = (*topRes)[1] + (*botRes)[1];

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

        // Build A/B vectors for both sides into local accumulators; these are
        // moved into freshly-allocated EvalKeyRelinImpl objects at the end.
        std::vector<DCRTPoly> topAVec(numPartQ), topBVec(numPartQ);
        std::vector<DCRTPoly> botAVec(numPartQ), botBVec(numPartQ);

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
                topAVec[part] = std::move(a);
                topBVec[part] = std::move(b);
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
                botAVec[part] = std::move(a);
                botBVec[part] = std::move(b);
            }
        }

        // Wrap the per-side vectors as EvalKeys so EvalFastKeySwitchCoreExt can
        // consume them directly. Reuses the secret key's CryptoContext (the
        // EvalKeyImpl base class needs it for GetCryptoParameters()).
        auto cc = secretKey->GetCryptoContext();
        auto topKey = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
        topKey->SetAVector(std::move(topAVec));
        topKey->SetBVector(std::move(topBVec));
        auto botKey = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
        botKey->SetAVector(std::move(botAVec));
        botKey->SetBVector(std::move(botBVec));

        RGSWCiphertext<DCRTPoly> G;
        G.top = std::move(topKey);
        G.bot = std::move(botKey);
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
    //   2. ModUp Q → QP via EvalKeySwitchPrecomputeCore.
    //   3. Two EvalFastKeySwitchCoreExt calls (one against A.top, one against
    //      A.bot), summed in QP, then a single ApproxModDown back to Q.
    //   4. Lift back to QP via TimesNoCheck(PModq), restoring the P factor
    //      that the RGSW gadget format requires.
    //
    // Same per-side accumulator pattern as EvalExternalProduct, but applied
    // 2·dnum times (once per (a, b) row of B) and with a final P-lift.
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
        if (!A.top || !A.bot || !B.top || !B.bot)
            throw std::runtime_error("EvalInternalProduct: RGSW operand has null top/bot key");

        const auto paramsQ   = cp->GetElementParams();
        const auto paramsQP  = cp->GetParamsQP();
        const uint32_t dnum  = static_cast<uint32_t>(A.size());
        const uint32_t sizeQ = paramsQ->GetParams().size();
        const auto& PModq    = cp->GetPModq();

        KeySwitchHYBRID ks;

        // Apply the external-product action of A to a single QP-basis row of
        // B, returning the resulting QP-basis (a', b') with the gadget P
        // factor restored.
        auto applyAToRow = [&](const DCRTPoly& aQP, const DCRTPoly& bQP) {
            // (1) Project from QP → Q, cancelling the gadget P factor.
            DCRTPoly aQ = ApproxModDownToQ(aQP, paramsQ);
            DCRTPoly bQ = ApproxModDownToQ(bQP, paramsQ);

            // (2) ModUp Q → QP and (3) two dot-products + add + ApproxModDown.
            auto uDig = ks.EvalKeySwitchPrecomputeCore(aQ, cp);
            auto vDig = ks.EvalKeySwitchPrecomputeCore(bQ, cp);

            auto topRes = ks.EvalFastKeySwitchCoreExt(uDig, A.top, paramsQ);
            auto botRes = ks.EvalFastKeySwitchCoreExt(vDig, A.bot, paramsQ);

            DCRTPoly r0 = (*topRes)[0] + (*botRes)[0];
            DCRTPoly r1 = (*topRes)[1] + (*botRes)[1];

            DCRTPoly out0Q = ApproxModDownToQ(r0, paramsQ);
            DCRTPoly out1Q = ApproxModDownToQ(r1, paramsQ);

            // (4) Lift back to QP with the P factor on Q-side, zeros on P-side.
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

        std::vector<DCRTPoly> topAVec(dnum), topBVec(dnum);
        std::vector<DCRTPoly> botAVec(dnum), botBVec(dnum);

        const auto& bTopA = B.top->GetAVector();
        const auto& bTopB = B.top->GetBVector();
        const auto& bBotA = B.bot->GetAVector();
        const auto& bBotB = B.bot->GetBVector();

        for (uint32_t j = 0; j < dnum; ++j) {
            auto top = applyAToRow(bTopA[j], bTopB[j]);
            auto bot = applyAToRow(bBotA[j], bBotB[j]);
            topAVec[j] = std::move(top.first);
            topBVec[j] = std::move(top.second);
            botAVec[j] = std::move(bot.first);
            botBVec[j] = std::move(bot.second);
        }

        auto cc = A.top->GetCryptoContext();
        auto outTop = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
        outTop->SetAVector(std::move(topAVec));
        outTop->SetBVector(std::move(topBVec));
        auto outBot = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
        outBot->SetAVector(std::move(botAVec));
        outBot->SetBVector(std::move(botBVec));

        RGSWCiphertext<DCRTPoly> C;
        C.top = std::move(outTop);
        C.bot = std::move(outBot);
        return C;
    }

    namespace {
        // Element-wise combine the two sides of two RGSWs with a binary op on
        // DCRTPoly (op is + or -). Both operands must have matching dnum and a
        // non-null top/bot key.
        template <typename Op>
        RGSWCiphertext<DCRTPoly> CombineRGSW(
            const RGSWCiphertext<DCRTPoly>& A,
            const RGSWCiphertext<DCRTPoly>& B,
            Op op,
            const char* opName
        ) {
            if (A.size() != B.size())
                throw std::runtime_error(std::string(opName) + ": dnum mismatch");
            if (!A.top || !A.bot || !B.top || !B.bot)
                throw std::runtime_error(std::string(opName) + ": RGSW operand has null top/bot key");

            const size_t d = A.size();
            auto combineSide = [&](const EvalKey<DCRTPoly>& a, const EvalKey<DCRTPoly>& b) {
                const auto& aA = a->GetAVector(); const auto& aB = a->GetBVector();
                const auto& bA = b->GetAVector(); const auto& bB = b->GetBVector();
                std::vector<DCRTPoly> outA, outB;
                outA.reserve(d); outB.reserve(d);
                for (size_t j = 0; j < d; ++j) {
                    outA.push_back(op(aA[j], bA[j]));
                    outB.push_back(op(aB[j], bB[j]));
                }
                auto out = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(a->GetCryptoContext());
                out->SetAVector(std::move(outA));
                out->SetBVector(std::move(outB));
                return out;
            };

            RGSWCiphertext<DCRTPoly> R;
            R.top = combineSide(A.top, B.top);
            R.bot = combineSide(A.bot, B.bot);
            return R;
        }
    }

    template <typename T>
    RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalAddRGSW(
        const RGSWCiphertext<DCRTPoly>& A,
        const RGSWCiphertext<DCRTPoly>& B
    ) {
        return CombineRGSW(A, B, [](const DCRTPoly& x, const DCRTPoly& y) { return x + y; }, "EvalAddRGSW");
    }

    template <typename T>
    RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalSubRGSW(
        const RGSWCiphertext<DCRTPoly>& A,
        const RGSWCiphertext<DCRTPoly>& B
    ) {
        return CombineRGSW(A, B, [](const DCRTPoly& x, const DCRTPoly& y) { return x - y; }, "EvalSubRGSW");
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

        if (!A.top || !A.bot)
            throw std::runtime_error("EvalMultPlain: RGSW operand has null top/bot key");

        const size_t dnum = A.size();
        auto scaleSide = [&](const EvalKey<DCRTPoly>& side) {
            const auto& aVec = side->GetAVector();
            const auto& bVec = side->GetBVector();
            std::vector<DCRTPoly> outA, outB;
            outA.reserve(dnum); outB.reserve(dnum);
            for (size_t j = 0; j < dnum; ++j) {
                outA.push_back(aVec[j] * pQP);
                outB.push_back(bVec[j] * pQP);
            }
            auto out = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(side->GetCryptoContext());
            out->SetAVector(std::move(outA));
            out->SetBVector(std::move(outB));
            return out;
        };

        RGSWCiphertext<DCRTPoly> R;
        R.top = scaleSide(A.top);
        R.bot = scaleSide(A.bot);
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
