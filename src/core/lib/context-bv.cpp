#include "../include/context-bv.h"
#include "key/privatekey.h"
#include "schemerns/rns-cryptoparameters.h"

#include "utils/timer.h"

namespace Context
{
    //------------------------//
    // BV-RNS IMPLEMENTATIONS //
    //------------------------//
    
    // TODO: Make separate context-bv.h/cpp and context-hybrid.h/cpp files
    //       And shared Context::MakeExtendedContext(Gadgets::BV)
    //       Consider also an implementation for the original version (with non-rns gadget decomp parameter)
    namespace BV {
        /**
         * @brief Construct the BV-RNS gadget scalars used in the gadget vector
         * 
         * Described in https://eprint.iacr.org/2021/204 and https://eprint.iacr.org/2016/510
         * 
         * @param cc The current (base) crypto context
         * @return std::vector<NativeInteger> with one NativeInteger per RNS-prime
         */
        static std::vector<NativeInteger> InverseGadgetScalars(const CryptoContextImpl<DCRTPoly>& cc) {
            const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc.GetCryptoParameters());
            const auto Q = params->GetElementParams()->GetModulus();
            const auto q = params->GetElementParams()->GetParams();
    
            std::vector<NativeInteger> result;
            result.reserve(q.size());
            for (size_t i = 0; i < q.size(); i++) {
                const auto qi = q[i]->GetModulus();
                result.push_back((Q / BigInteger(qi)).Mod(qi).ModInverse(qi));
            }
            return result;
        }

        /**
         * @brief Construct the BV-RNS gadget scalars used in the inverse gadget decomposition
         * 
         * Described in https://eprint.iacr.org/2021/204 and https://eprint.iacr.org/2016/510
         * 
         * @param cc The current (base) crypto context
         * @return std::vector<NativeInteger> with one NativeInteger per RNS-prime
         */
        static std::vector<NativeInteger> GadgetScalars(const CryptoContextImpl<DCRTPoly>& cc) {
            const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc.GetCryptoParameters());
            const auto Q = params->GetElementParams()->GetModulus();
            const auto q = params->GetElementParams()->GetParams();

            std::vector<NativeInteger> result;
            result.reserve(q.size());
            for (size_t i = 0; i < q.size(); i++) {
                const auto qi = q[i]->GetModulus();
                result.push_back((Q / BigInteger(qi)).Mod(qi));
            }
            return result;
        }
    }

    ExtendedCryptoContextImpl::ExtendedCryptoContextImpl(const CryptoContextImpl<DCRTPoly>& base)
    : CryptoContextImpl<DCRTPoly>(base), m_gadgetVectorScalars(BV::GadgetScalars(base)), m_gadgetDecompVectorScalars(BV::InverseGadgetScalars(base)) {}

    /// @brief Return RGSW ciphertext
    RGSW ExtendedCryptoContextImpl::EncryptRGSW(const PublicKey<DCRTPoly>& publicKey, const Plaintext& plaintext) const
    {
        // Mirror the input encoding: Encrypt() stamps the plaintext's encoding type onto
        // the ciphertext, so every RGSW row must use the same encoding the caller expects
        // to decrypt with (COEF_PACKED → GetCoefPackedValue, PACKED → GetPackedValue).
        const auto zero = (plaintext->GetEncodingType() == COEF_PACKED_ENCODING)
            ? this->MakeCoefPackedPlaintext({0})
            : this->MakePackedPlaintext({0});
        const auto mg = GadgetMul(plaintext->GetElement<DCRTPoly>());
        
        std::vector<Ciphertext<DCRTPoly>> rgsw;
        rgsw.reserve(2*mg.size());

        // auto Z = this->Encrypt(publicKey, zero);
        
        for(size_t col = 0; col < 2; col++) {
            for(const auto& mgi : mg) {
                // Using fresh encryptions is slower (1.63ms vs 0.517ms)
                auto z = this->Encrypt(publicKey, zero);
                // auto z = Z->Clone();
                z->GetElements()[col] += mgi;
                rgsw.push_back(std::move(z));
            }
        }

        return rgsw;
    }

    /// @brief Returns the external product between the rlwe and rgsw
    RLWE ExtendedCryptoContextImpl::EvalExternalProduct(const RLWE &rlwe, const RGSW &rgsw) const
    {
        auto c0 = rlwe->GetElements()[0];
        auto c1 = rlwe->GetElements()[1];
        c0.SetFormat(Format::EVALUATION);
        c1.SetFormat(Format::EVALUATION);

        const auto d0 = Decompose(c0);
        const auto d1 = Decompose(c1);
        const size_t K = d0.size();  // L * ell

        // Build outputs at the RLWE's active level, not the full context chain.
        const auto& activeParams = c0.GetParams();
        DCRTPoly out0(activeParams, Format::EVALUATION, true);
        DCRTPoly out1(activeParams, Format::EVALUATION, true);
        for (size_t i = 0; i < K; i++) {
            const auto& m0 = rgsw[i]->GetElements();
            const auto& m1 = rgsw[K + i]->GetElements();
            out0 += d0[i] * m0[0];
            out1 += d0[i] * m0[1];
            out0 += d1[i] * m1[0];
            out1 += d1[i] * m1[1];
        }

        auto result = rlwe->Clone();
        result->GetElements()[0] = std::move(out0);
        result->GetElements()[1] = std::move(out1);

        return result;
    }

    RGSW ExtendedCryptoContextImpl::EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const
    {
        RGSW result = lhs;
        for(auto& rlwe : result) {
            rlwe = EvalExternalProduct(rlwe, rhs);
        }
        return result;
    }

    // DecryptResult ExtendedCryptoContextImpl::Decrypt(const RGSW &ciphertext, const PrivateKey<DCRTPoly> &privateKey, Plaintext *plaintext) const
    // {
    //     const auto rlwe = ciphertext[ciphertext.size()/2];
    //     return CryptoContextImpl<DCRTPoly>::Decrypt(rlwe, privateKey, &plaintext);
    // }

    /// @brief Number of base-GADGET_BASE digits needed to cover the largest RNS prime.
    /// Digits per tower: ell = ceil(log_GADGET_BASE(max_qi)).
    size_t ExtendedCryptoContextImpl::GadgetDigits() const {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const auto& q = params->GetElementParams()->GetParams();
        uint64_t maxQi = 0;
        for (const auto& qp : q)
            maxQi = std::max(maxQi, qp->GetModulus().ConvertToInt<uint64_t>());
        size_t ell = 0;
        for (uint64_t v = maxQi; v > 0; v >>= GADGET_LOG) ++ell;
        return ell;
    }

    /// @brief Two-level BV-RNS decomposition: outer level = RNS tower, inner level = base-GADGET_BASE.
    ///
    /// For each tower i, computes the unit digit u_i = a_i · (Q/q_i)^{-1} mod q_i (values in [0, q_i)),
    /// then splits u_i into ell base-GADGET_BASE digits: u_i = Σ_j d_{i,j} · GADGET_BASE^j.
    /// Each d_{i,j} is a polynomial with coefficients in [0, GADGET_BASE) and is embedded consistently
    /// across all RNS towers via SwitchModulus so that products d_{i,j} · e_k remain bounded by
    /// GADGET_BASE/2 · ||e|| instead of q_i/2 · ||e||.
    ///
    /// Returns L·ell DCRTPolys in EVALUATION format.
    std::vector<DCRTPoly> ExtendedCryptoContextImpl::Decompose(const DCRTPoly& a) const {
        // Derive L and params from the polynomial itself so that leveled ciphertexts
        // that have dropped towers don't cause out-of-bounds GetElementAtIndex calls.
        const auto& activeParams = a.GetParams();
        const auto& q = activeParams->GetParams();
        const size_t L = q.size();
        const size_t N = this->GetRingDimension();

        // Compute ell from the active towers' max modulus, not the full context chain.
        uint64_t maxQi = 0;
        for (const auto& qp : q)
            maxQi = std::max(maxQi, qp->GetModulus().ConvertToInt<uint64_t>());
        size_t ell = 0;
        for (uint64_t v = maxQi; v > 0; v >>= GADGET_LOG) ++ell;

        DCRTPoly aCoef(a);
        aCoef.SetFormat(Format::COEFFICIENT);

        std::vector<DCRTPoly> d;
        d.reserve(L * ell);

        for (size_t i = 0; i < L; i++) {
            const auto qi = q[i]->GetModulus();
            const uint64_t qiVal = qi.ConvertToInt<uint64_t>();
            // u_i = a_i · (Q/q_i)^{-1} mod q_i   (values in [0, q_i))
            auto unit = aCoef.GetElementAtIndex(i).Times(m_gadgetDecompVectorScalars[i]).Mod(qi);

            // Per-coefficient signed running remainder for base-GADGET_BASE recoding.
            // Center u_i to [-q_i/2, q_i/2) so that ell signed digits suffice; each iteration
            // peels one digit in [-B/2, B/2) and propagates the borrow into the next.
            std::vector<int64_t> rem(N);
            const int64_t qiSigned = static_cast<int64_t>(qiVal);
            for (size_t k = 0; k < N; k++) {
                const uint64_t u = unit[k].ConvertToInt<uint64_t>();
                rem[k] = (u >= qiVal / 2) ? static_cast<int64_t>(u) - qiSigned
                                          : static_cast<int64_t>(u);
            }

            for (size_t j = 0; j < ell; j++) {
                NativePoly digitPoly(unit);   // copies params (modulus = q_i)
                for (size_t k = 0; k < N; k++) {
                    const int64_t c     = rem[k];
                    // Power-of-two base: low GADGET_LOG bits of two's-complement c == c mod B.
                    const uint64_t udigit = static_cast<uint64_t>(c) & (GADGET_BASE - 1);
                    int64_t newRem        = c >> GADGET_LOG;   // arithmetic shift = floor(c / B)
                    uint64_t stored;
                    if (udigit >= GADGET_BASE / 2) {
                        // Signed digit = udigit - B (negative); store as q_i - (B - udigit) mod q_i.
                        stored = qiVal - (GADGET_BASE - udigit);
                        newRem += 1;
                    } else {
                        stored = udigit;
                    }
                    rem[k]       = newRem;
                    digitPoly[k] = NativeInteger(stored);
                }

                // Embed consistently: same small polynomial in every active tower.
                DCRTPoly di(activeParams, Format::COEFFICIENT, true);
                for (size_t t = 0; t < L; t++) {
                    if (t == i) {
                        di.SetElementAtIndex(t, digitPoly);
                    } else {
                        auto tk = digitPoly;
                        tk.SwitchModulus(q[t]->GetModulus(), q[t]->GetRootOfUnity(), 0, 0);
                        di.SetElementAtIndex(t, std::move(tk));
                    }
                }
                di.SetFormat(Format::EVALUATION);
                d.push_back(std::move(di));
            }
        }

        return d;
    }

    /// @brief P_Q(b)_{i,j} = [b*(Q/q_i)*GADGET_BASE^j]_{q_i}. Returns L*ell elements; only tower i non-zero.
    std::vector<DCRTPoly> ExtendedCryptoContextImpl::GadgetMul(const DCRTPoly& b) const {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const auto& q = params->GetElementParams()->GetParams();
        const size_t L   = q.size();
        const size_t ell = GadgetDigits();

        std::vector<DCRTPoly> P;
        P.reserve(L * ell);

        for (size_t i = 0; i < L; i++) {
            const auto qi = q[i]->GetModulus();
            auto baseTower = b.GetElementAtIndex(i).Times(m_gadgetVectorScalars[i]).Mod(qi);

            NativeInteger powerOfBase(1);
            for (size_t j = 0; j < ell; j++) {
                auto tower = baseTower.Times(powerOfBase).Mod(qi);

                DCRTPoly Pi(params->GetElementParams(), b.GetFormat(), true);
                Pi.SetElementAtIndex(i, tower);
                P.push_back(std::move(Pi));

                powerOfBase = powerOfBase.ModMul(NativeInteger(GADGET_BASE), qi);
            }
        }

        return P;
    }

    /// @brief Gadget vector g_{i,j} = [(Q/q_i)*GADGET_BASE^j]_Q. Returns L*ell elements; only tower i non-zero.
    std::vector<DCRTPoly> ExtendedCryptoContextImpl::GadgetVector() const {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const auto& q = params->GetElementParams()->GetParams();
        const size_t L   = q.size();
        const size_t ell = GadgetDigits();

        std::vector<DCRTPoly> out;
        out.reserve(L * ell);
        for (size_t i = 0; i < L; i++) {
            const auto qi = q[i]->GetModulus();
            NativeInteger powerOfBase(1);
            for (size_t j = 0; j < ell; j++) {
                auto gij = m_gadgetVectorScalars[i].ModMul(powerOfBase, qi);

                DCRTPoly poly(params->GetElementParams(), Format::COEFFICIENT, true);
                auto tower = poly.GetElementAtIndex(i);
                tower[0] = gij;
                poly.SetElementAtIndex(i, tower);
                poly.SetFormat(Format::EVALUATION);
                out.push_back(std::move(poly));

                powerOfBase = powerOfBase.ModMul(NativeInteger(GADGET_BASE), qi);
            }
        }
        return out;
    }


    //--------------//
    // RLWE-to-RGSW //
    //--------------//

    /// @todo Check if still works
    std::vector<Ciphertext<DCRTPoly>> ExtendedCryptoContextImpl::ExpandRLWEHoisted(
        const Ciphertext<DCRTPoly>& ciphertext,
        const PublicKey<DCRTPoly>& publicKey,
        const uint32_t len
    ) {
        const auto ciphertext_n = this->Encrypt(publicKey, this->MakePackedPlaintext({ 1 }));

        std::vector<Ciphertext<DCRTPoly>> c(len);
        c[0] = this->EvalMult(ciphertext, ciphertext_n);

        const auto precomputed = this->EvalFastRotationPrecompute(ciphertext);
        for (uint32_t i = 1; i < len; i++) {
            const auto rotated = this->EvalFastRotation(ciphertext, i, precomputed);
            c[i] = this->EvalMult(rotated, ciphertext_n);
        }

        return c;
    }
}



//     // ----------------------------------------------------------------------
//     // Helper: ApproxModDown a single QP DCRTPoly back to Q (BGV t-aware).
//     // Mirrors the call at keyswitch-hybrid.cpp:389-398.
//     // ----------------------------------------------------------------------
//     template <typename T>
//     DCRTPoly ExtendedCryptoContextImpl<T>::ApproxModDownToQ(
//         const DCRTPoly& xQP,
//         const std::shared_ptr<typename DCRTPoly::Params>& paramsQl
//     ) const {
//         const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
//         const PlaintextModulus t = (cp->GetNoiseScale() == 1) ? 0 : cp->GetPlaintextModulus();
//         return xQP.ApproxModDown(
//             paramsQl, cp->GetParamsP(),
//             cp->GetPInvModq(),    cp->GetPInvModqPrecon(),
//             cp->GetPHatInvModp(), cp->GetPHatInvModpPrecon(),
//             cp->GetPHatModq(),    cp->GetModqBarrettMu(),
//             cp->GettInvModp(),    cp->GettInvModpPrecon(),
//             t,                    cp->GettModqPrecon());
//     }

//     // ----------------------------------------------------------------------
//     // External product: RLWE × RGSW → RLWE.
//     //
//     //   1 ModUp on each RLWE component (via EvalKeySwitchPrecomputeCore)
//     // + 2 EvalFastKeySwitchCoreExt calls (one per RGSW side, dot product in QlP)
//     // + tower-wise add of the two QlP results
//     // + 2 ApproxModDown back to Ql (via the BGV-t-aware helper).
//     //
//     // Per-level alignment is automatic: EvalFastKeySwitchCoreExt uses the
//     // `delta = sizeQ - sizeQl` skip pattern when indexing into the full-Q
//     // EvalKey, so mod-reduced x against full-Q Y just works.
//     // ----------------------------------------------------------------------
//     template <typename T>
//     Ciphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalExternalProduct(
//         const Ciphertext<DCRTPoly>& x,
//         const RGSWCiphertext<DCRTPoly>& Y
//     ) {
//         // DEBUG_TIMER("External Product");

//         const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
//         if (!cp)
//             throw std::runtime_error("EvalExternalProduct: cryptoparams not RNS");
//         if (!Y.top || !Y.bot)
//             throw std::runtime_error("EvalExternalProduct: RGSW operand has null top/bot key");

//         const auto& cv = x->GetElements();
//         const auto paramsQl = cv[0].GetParams();

//         KeySwitchHYBRID ks;
//         auto vDigits = ks.EvalKeySwitchPrecomputeCore(cv[0], cp);  // b → digits
//         auto uDigits = ks.EvalKeySwitchPrecomputeCore(cv[1], cp);  // a → digits

//         if (uDigits->size() > Y.size())
//             throw std::runtime_error("EvalExternalProduct: RGSW has fewer digits than current level requires");

//         // Two dot products in QlP via OpenFHE's primitive (delta-skip + OMP).
//         auto topRes = ks.EvalFastKeySwitchCoreExt(uDigits, Y.top, paramsQl);
//         auto botRes = ks.EvalFastKeySwitchCoreExt(vDigits, Y.bot, paramsQl);

//         // Sum the two sides in QlP, then a single shared ApproxModDown per slot.
//         DCRTPoly r0 = (*topRes)[0] + (*botRes)[0];
//         DCRTPoly r1 = (*topRes)[1] + (*botRes)[1];

//         auto out0 = ApproxModDownToQ(r0, paramsQl);
//         auto out1 = ApproxModDownToQ(r1, paramsQl);

//         auto result = x->CloneEmpty();
//         result->SetElements({ std::move(out0), std::move(out1) });
//         result->SetLevel(x->GetLevel());
//         result->SetNoiseScaleDeg(x->GetNoiseScaleDeg());
//         return result;
//     }

//     // ----------------------------------------------------------------------
//     // Encrypt RGSW: build dnum (a, b) pairs in QP basis per side.
//     //
//     // Mirrors KeySwitchHYBRID::KeySwitchGenInternal(privateKey, privateKey)
//     // exactly, with `m` playing the role of `sOld` for both sides:
//     //   top: sOld ↦ m * s   (result row encrypts m * P * g_j * s)
//     //   bot: sOld ↦ m       (result row encrypts m * P * g_j)
//     // ----------------------------------------------------------------------
//     template <typename T>
//     RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EncryptRGSW(
//         const PrivateKey<DCRTPoly>& secretKey,
//         const Plaintext& plaintext
//     ) {
//         // DEBUG_TIMER("Encrypt RGSW");

//         const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
//         if (!cp)
//             throw std::runtime_error("EncryptRGSW: cryptoparams not RNS");

//         const auto paramsQ  = cp->GetElementParams();
//         const auto paramsQP = cp->GetParamsQP();
//         const auto& pparamsQP = paramsQP->GetParams();
//         const uint32_t sizeQ  = paramsQ->GetParams().size();
//         const uint32_t sizeQP = paramsQP->GetParams().size();

//         const uint32_t numPerPartQ = cp->GetNumPerPartQ();
//         const uint32_t numPartQ    = cp->GetNumPartQ();

//         // Encode message as DCRTPoly in Q.
//         // Plaintext mPlain = this->MakePackedPlaintext(msg);
//         // if (!mPlain->Encode())
//         //     throw std::runtime_error("EncryptRGSW: failed to encode plaintext");
//         DCRTPoly mDCRT = plaintext->GetElement<DCRTPoly>();
//         mDCRT.SetFormat(Format::EVALUATION);

//         // Build m*s in Q (used for top rows). m is the message; s is the secret.
//         const auto& sQ = secretKey->GetPrivateElement();
//         DCRTPoly msQ = mDCRT * sQ;

//         // Extend secret s to QP (mirrors KeySwitchGenInternal lines 61-83).
//         DCRTPoly sExt(paramsQP, Format::EVALUATION, true);
//         auto s0 = sQ.GetElementAtIndex(0);
//         s0.SetFormat(Format::COEFFICIENT);
// #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQP))
//         for (uint32_t i = 0; i < sizeQP; ++i) {
//             if (i < sizeQ) {
//                 auto tmp = sQ.GetElementAtIndex(i);
//                 tmp.SetFormat(Format::EVALUATION);
//                 sExt.SetElementAtIndex(i, std::move(tmp));
//             } else {
//                 auto tmp = s0;
//                 tmp.SwitchModulus(pparamsQP[i]->GetModulus(), pparamsQP[i]->GetRootOfUnity(), 0, 0);
//                 tmp.SetFormat(Format::EVALUATION);
//                 sExt.SetElementAtIndex(i, std::move(tmp));
//             }
//         }

//         const auto ns = cp->GetNoiseScale();
//         const auto& PModq = cp->GetPModq();
//         auto dgg = cp->GetDiscreteGaussianGenerator();
//         typename DCRTPoly::DugType dug;

//         // Build A/B vectors for both sides into local accumulators; these are
//         // moved into freshly-allocated EvalKeyRelinImpl objects at the end.
//         std::vector<DCRTPoly> topAVec(numPartQ), topBVec(numPartQ);
//         std::vector<DCRTPoly> botAVec(numPartQ), botBVec(numPartQ);

//         // For each partition j, build (a, b) pair for top and bot.
//         // Mirrors keyswitch-hybrid.cpp:98 — outer parallel with private RNGs.
// #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numPartQ)) private(dug, dgg)
//         for (uint32_t part = 0; part < numPartQ; ++part) {
//             const uint32_t startPartIdx = numPerPartQ * part;
//             const uint32_t endPartIdx   = (sizeQ > startPartIdx + numPerPartQ) ? (startPartIdx + numPerPartQ) : sizeQ;

//             // ---- top side: payload = m * s in Q-side ∩ partition_j ----
//             {
//                 DCRTPoly a(dug, paramsQP, Format::EVALUATION);
//                 DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
//                 DCRTPoly b(paramsQP, Format::EVALUATION, true);
//                 for (uint32_t i = 0; i < sizeQP; ++i) {
//                     const auto& ai  = a.GetElementAtIndex(i);
//                     const auto& ei  = e.GetElementAtIndex(i);
//                     const auto& sni = sExt.GetElementAtIndex(i);
//                     if (i < startPartIdx || i >= endPartIdx) {
//                         b.SetElementAtIndex(i, (-ai * sni) + (ns * ei));
//                     } else {
//                         const auto& msi = msQ.GetElementAtIndex(i);  // (m * s) in tower i (i < sizeQ here)
//                         b.SetElementAtIndex(i, (-ai * sni) + (ns * ei) + (PModq[i] * msi));
//                     }
//                 }
//                 topAVec[part] = std::move(a);
//                 topBVec[part] = std::move(b);
//             }

//             // ---- bot side: payload = m in Q-side ∩ partition_j ----
//             {
//                 DCRTPoly a(dug, paramsQP, Format::EVALUATION);
//                 DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
//                 DCRTPoly b(paramsQP, Format::EVALUATION, true);
//                 for (uint32_t i = 0; i < sizeQP; ++i) {
//                     const auto& ai  = a.GetElementAtIndex(i);
//                     const auto& ei  = e.GetElementAtIndex(i);
//                     const auto& sni = sExt.GetElementAtIndex(i);
//                     if (i < startPartIdx || i >= endPartIdx) {
//                         b.SetElementAtIndex(i, (-ai * sni) + (ns * ei));
//                     } else {
//                         const auto& mi = mDCRT.GetElementAtIndex(i);
//                         b.SetElementAtIndex(i, (-ai * sni) + (ns * ei) + (PModq[i] * mi));
//                     }
//                 }
//                 botAVec[part] = std::move(a);
//                 botBVec[part] = std::move(b);
//             }
//         }

//         // Wrap the per-side vectors as EvalKeys so EvalFastKeySwitchCoreExt can
//         // consume them directly. Reuses the secret key's CryptoContext (the
//         // EvalKeyImpl base class needs it for GetCryptoParameters()).
//         auto cc = secretKey->GetCryptoContext();
//         auto topKey = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
//         topKey->SetAVector(std::move(topAVec));
//         topKey->SetBVector(std::move(topBVec));
//         auto botKey = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
//         botKey->SetAVector(std::move(botAVec));
//         botKey->SetBVector(std::move(botBVec));

//         RGSWCiphertext<DCRTPoly> G;
//         G.top = std::move(topKey);
//         G.bot = std::move(botKey);
//         return G;
//     }

//     // ----------------------------------------------------------------------
//     // Test/debug: decrypt one QP-basis (a, b) row by projecting back to Q
//     // (ApproxModDown cancels the P factor) then doing the standard BGV
//     // decryption b + a*s mod t.
//     // ----------------------------------------------------------------------
//     template <typename T>
//     Plaintext ExtendedCryptoContextImpl<T>::DecryptRGSWRow(
//         const PrivateKey<DCRTPoly>& secretKey,
//         const DCRTPoly& a,
//         const DCRTPoly& b
//     ) {
//         const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
//         const auto paramsQ = cp->GetElementParams();

//         DCRTPoly aQ = ApproxModDownToQ(a, paramsQ);
//         DCRTPoly bQ = ApproxModDownToQ(b, paramsQ);

//         // Construct a fresh ciphertext bound to the same CryptoContext as the
//         // secret key (the Ciphertext(Key) ctor steals the context from the key).
//         auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(
//             std::static_pointer_cast<Key<DCRTPoly>>(secretKey));
//         ct->SetElements({ std::move(bQ), std::move(aQ) });
//         ct->SetEncodingType(PACKED_ENCODING);
//         ct->SetLevel(0);
//         ct->SetNoiseScaleDeg(1);

//         Plaintext pt;
//         this->Decrypt(secretKey, ct, &pt);
//         return pt;
//     }

//     // ----------------------------------------------------------------------
//     // Internal product: RGSW × RGSW → RGSW.
//     //
//     // For each (a, b) row of B (top and bot, dnum each):
//     //   1. ApproxModDown the row from QP → Q  (cancels the gadget P factor,
//     //      leaving an RLWE ciphertext that encrypts m_B · g_j  [bot]
//     //      or  m_B · g_j · s  [top]).
//     //   2. ModUp Q → QP via EvalKeySwitchPrecomputeCore.
//     //   3. Two EvalFastKeySwitchCoreExt calls (one against A.top, one against
//     //      A.bot), summed in QP. The QP result is *already* in RGSW gadget
//     //      format — the dot-product introduces a P factor on Q-side in the
//     //      partition we're processing and ≈ 0 elsewhere — so we keep it as-is.
//     //
//     // The original implementation rounded the QP result back to Q (one extra
//     // ApproxModDown per side) and then multiplied by P to "re-lift" — that's
//     // algebraically near-identity but a noise amplifier and a wasted pass.
//     // Skipping it cuts 4 ApproxModDowns + the P-lift loop out of every B-row
//     // and lowers the depth budget needed by the composed Internal+External.
//     // ----------------------------------------------------------------------
//     template <typename T>
//     RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalInternalProduct(
//         const RGSWCiphertext<DCRTPoly>& A,
//         const RGSWCiphertext<DCRTPoly>& B
//     ) {
//         // DEBUG_TIMER("Internal Product");

//         const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
//         if (!cp)
//             throw std::runtime_error("EvalInternalProduct: cryptoparams not RNS");
//         if (A.size() != B.size())
//             throw std::runtime_error("EvalInternalProduct: dnum mismatch");
//         if (!A.top || !A.bot || !B.top || !B.bot)
//             throw std::runtime_error("EvalInternalProduct: RGSW operand has null top/bot key");

//         const auto paramsQ  = cp->GetElementParams();
//         const uint32_t dnum = static_cast<uint32_t>(A.size());

//         KeySwitchHYBRID ks;

//         // Apply the external-product action of A to a single QP-basis row of
//         // B, returning the resulting QP-basis (a', b') already in RGSW gadget
//         // format for the same partition index this row came from.
//         auto applyAToRow = [&](const DCRTPoly& aQP, const DCRTPoly& bQP) {
//             // (1) Project QP → Q, cancelling the gadget P factor in B's row.
//             DCRTPoly aQ = ApproxModDownToQ(aQP, paramsQ);
//             DCRTPoly bQ = ApproxModDownToQ(bQP, paramsQ);

//             // (2) ModUp Q → QP digits.
//             auto uDig = ks.EvalKeySwitchPrecomputeCore(aQ, cp);
//             auto vDig = ks.EvalKeySwitchPrecomputeCore(bQ, cp);

//             // (3) Two dot-products in QP, summed. r0 ↔ B-side, r1 ↔ A-side.
//             // r0 + r1·s ≈ m_A · P · embed_Q(b_Q + a_Q·s) = m_A · m_B · P · g_j,
//             // i.e., already an RGSW row. No ApproxModDown / re-lift needed.
//             auto topRes = ks.EvalFastKeySwitchCoreExt(uDig, A.top, paramsQ);
//             auto botRes = ks.EvalFastKeySwitchCoreExt(vDig, A.bot, paramsQ);

//             DCRTPoly r0 = (*topRes)[0] + (*botRes)[0];
//             DCRTPoly r1 = (*topRes)[1] + (*botRes)[1];

//             return std::pair<DCRTPoly, DCRTPoly>{ std::move(r1), std::move(r0) };
//         };

//         std::vector<DCRTPoly> topAVec(dnum), topBVec(dnum);
//         std::vector<DCRTPoly> botAVec(dnum), botBVec(dnum);

//         const auto& bTopA = B.top->GetAVector();
//         const auto& bTopB = B.top->GetBVector();
//         const auto& bBotA = B.bot->GetAVector();
//         const auto& bBotB = B.bot->GetBVector();

//         for (uint32_t j = 0; j < dnum; ++j) {
//             auto top = applyAToRow(bTopA[j], bTopB[j]);
//             auto bot = applyAToRow(bBotA[j], bBotB[j]);
//             topAVec[j] = std::move(top.first);
//             topBVec[j] = std::move(top.second);
//             botAVec[j] = std::move(bot.first);
//             botBVec[j] = std::move(bot.second);
//         }

//         auto cc = A.top->GetCryptoContext();
//         auto outTop = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
//         outTop->SetAVector(std::move(topAVec));
//         outTop->SetBVector(std::move(topBVec));
//         auto outBot = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);
//         outBot->SetAVector(std::move(botAVec));
//         outBot->SetBVector(std::move(botBVec));

//         RGSWCiphertext<DCRTPoly> C;
//         C.top = std::move(outTop);
//         C.bot = std::move(outBot);
//         return C;
//     }

//     // ----------------------------------------------------------------------
//     // Hybrid Internal product: RGSW × RGSW → RGSW.
//     //
//     // Textbook decomposition built on the working RNS external-product kernel:
//     //   for each row j (top and bot) of B:
//     //     1. ApproxModDown row from QP → Q  (cancels gadget P factor).
//     //     2. Wrap as Ciphertext<DCRTPoly> in Q.
//     //     3. EvalExternalProduct(rlwe, A) → Q-basis RLWE encrypting
//     //          m_A · m_B · g_j   (top: also includes ·s factor)
//     //     4. Re-pack into the QP-basis RGSW row format expected downstream:
//     //          a' in QP: scale a_Q by P (PModq) in Q-towers, zero P-towers.
//     //          b' in QP: same treatment.
//     //
//     // The repack mirrors how `EncryptRGSW` builds rows except we skip the
//     // fresh `-a*s + e` randomization on P-towers (we leave them at 0). The
//     // resulting rows decrypt the same way under ApproxModDown(QP→Q), and are
//     // consumable by EvalExternalProduct via EvalFastKeySwitchCoreExt (P-side
//     // contributes 0 to the dot product).
//     // ----------------------------------------------------------------------
//     template <typename T>
//     RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalInternalProduct_Hybrid(
//         const RGSWCiphertext<DCRTPoly>& A,
//         const RGSWCiphertext<DCRTPoly>& B
//     ) {
//         // DEBUG_TIMER("Internal Product (Hybrid)");

//         const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
//         if (!cp)
//             throw std::runtime_error("EvalInternalProduct_Hybrid: cryptoparams not RNS");
//         if (A.size() != B.size())
//             throw std::runtime_error("EvalInternalProduct_Hybrid: dnum mismatch");
//         if (!A.top || !A.bot || !B.top || !B.bot)
//             throw std::runtime_error("EvalInternalProduct_Hybrid: RGSW operand has null top/bot key");

//         const auto paramsQ  = cp->GetElementParams();
//         const auto paramsQP = cp->GetParamsQP();
//         const auto& pparamsQP = paramsQP->GetParams();
//         const auto& PModq = cp->GetPModq();
//         const uint32_t sizeQ  = paramsQ->GetParams().size();
//         const uint32_t sizeQP = pparamsQP.size();
//         const uint32_t dnum   = static_cast<uint32_t>(B.size());

//         auto ccBase = A.top->GetCryptoContext();

//         // Treat one QP-basis (a, b) row of B as an RLWE in Q after ModDown.
//         auto rowToRlwe = [&](const DCRTPoly& aQP, const DCRTPoly& bQP) {
//             DCRTPoly aQ = ApproxModDownToQ(aQP, paramsQ);
//             DCRTPoly bQ = ApproxModDownToQ(bQP, paramsQ);
//             auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(ccBase);
//             // BGV ciphertext layout: elements = { b, a }
//             ct->SetElements({ std::move(bQ), std::move(aQ) });
//             ct->SetEncodingType(PACKED_ENCODING);
//             ct->SetLevel(0);
//             ct->SetNoiseScaleDeg(1);
//             return ct;
//         };

//         // Lift a Q-basis DCRTPoly to QP by zero-padding the P-towers, and
//         // multiply Q-towers by P (PModq) so the row encodes m·P·g_j again.
//         auto qToQp_scaledByP = [&](const DCRTPoly& xQ) {
//             DCRTPoly y(paramsQP, Format::EVALUATION, true);
//             for (uint32_t i = 0; i < sizeQP; ++i) {
//                 if (i < sizeQ) {
//                     auto t = xQ.GetElementAtIndex(i);
//                     t.SetFormat(Format::EVALUATION);
//                     t *= PModq[i];
//                     y.SetElementAtIndex(i, std::move(t));
//                 }
//             }
//             return y;
//         };

//         std::vector<DCRTPoly> topAVec(dnum), topBVec(dnum);
//         std::vector<DCRTPoly> botAVec(dnum), botBVec(dnum);

//         const auto& bTopA = B.top->GetAVector();
//         const auto& bTopB = B.top->GetBVector();
//         const auto& bBotA = B.bot->GetAVector();
//         const auto& bBotB = B.bot->GetBVector();

//         // Process top side of B.
//         for (uint32_t j = 0; j < dnum; ++j) {
//             auto rlwe = rowToRlwe(bTopA[j], bTopB[j]);
//             auto out  = EvalExternalProduct(rlwe, A);
//             const auto& cv = out->GetElements();  // { b_Q, a_Q }
//             topBVec[j] = qToQp_scaledByP(cv[0]);
//             topAVec[j] = qToQp_scaledByP(cv[1]);
//         }
//         // Process bot side of B.
//         for (uint32_t j = 0; j < dnum; ++j) {
//             auto rlwe = rowToRlwe(bBotA[j], bBotB[j]);
//             auto out  = EvalExternalProduct(rlwe, A);
//             const auto& cv = out->GetElements();
//             botBVec[j] = qToQp_scaledByP(cv[0]);
//             botAVec[j] = qToQp_scaledByP(cv[1]);
//         }

//         auto outTop = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(ccBase);
//         outTop->SetAVector(std::move(topAVec));
//         outTop->SetBVector(std::move(topBVec));
//         auto outBot = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(ccBase);
//         outBot->SetAVector(std::move(botAVec));
//         outBot->SetBVector(std::move(botBVec));

//         RGSWCiphertext<DCRTPoly> C;
//         C.top = std::move(outTop);
//         C.bot = std::move(outBot);
//         return C;
//     }

//     namespace {
//         // Element-wise combine the two sides of two RGSWs with a binary op on
//         // DCRTPoly (op is + or -). Both operands must have matching dnum and a
//         // non-null top/bot key.
//         template <typename Op>
//         RGSWCiphertext<DCRTPoly> CombineRGSW(
//             const RGSWCiphertext<DCRTPoly>& A,
//             const RGSWCiphertext<DCRTPoly>& B,
//             Op op,
//             const char* opName
//         ) {
//             if (A.size() != B.size())
//                 throw std::runtime_error(std::string(opName) + ": dnum mismatch");
//             if (!A.top || !A.bot || !B.top || !B.bot)
//                 throw std::runtime_error(std::string(opName) + ": RGSW operand has null top/bot key");

//             const size_t d = A.size();
//             auto combineSide = [&](const EvalKey<DCRTPoly>& a, const EvalKey<DCRTPoly>& b) {
//                 const auto& aA = a->GetAVector(); const auto& aB = a->GetBVector();
//                 const auto& bA = b->GetAVector(); const auto& bB = b->GetBVector();
//                 std::vector<DCRTPoly> outA, outB;
//                 outA.reserve(d); outB.reserve(d);
//                 for (size_t j = 0; j < d; ++j) {
//                     outA.push_back(op(aA[j], bA[j]));
//                     outB.push_back(op(aB[j], bB[j]));
//                 }
//                 auto out = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(a->GetCryptoContext());
//                 out->SetAVector(std::move(outA));
//                 out->SetBVector(std::move(outB));
//                 return out;
//             };

//             RGSWCiphertext<DCRTPoly> R;
//             R.top = combineSide(A.top, B.top);
//             R.bot = combineSide(A.bot, B.bot);
//             return R;
//         }
//     }

//     template <typename T>
//     RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalAddRGSW(
//         const RGSWCiphertext<DCRTPoly>& A,
//         const RGSWCiphertext<DCRTPoly>& B
//     ) {
//         return CombineRGSW(A, B, [](const DCRTPoly& x, const DCRTPoly& y) { return x + y; }, "EvalAddRGSW");
//     }

//     template <typename T>
//     RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalSubRGSW(
//         const RGSWCiphertext<DCRTPoly>& A,
//         const RGSWCiphertext<DCRTPoly>& B
//     ) {
//         return CombineRGSW(A, B, [](const DCRTPoly& x, const DCRTPoly& y) { return x - y; }, "EvalSubRGSW");
//     }

//     // ----------------------------------------------------------------------
//     // Plaintext × RGSW: scale every QP-basis (a, b) row by the plaintext.
//     //
//     // Encode the plaintext to its Q-basis DCRTPoly, lift to QP (Q-side as is,
//     // P-side via SwitchModulus on each P-tower — same pattern used to extend
//     // the secret key in EncryptRGSW), then element-wise multiply each of
//     // topA/topB/botA/botB by the lifted polynomial. Linearity preserves the
//     // RGSW gadget structure: row j now encrypts (m · p) · P · g_j.
//     // ----------------------------------------------------------------------
//     template <typename T>
//     RGSWCiphertext<DCRTPoly> ExtendedCryptoContextImpl<T>::EvalMultPlain(
//         const Plaintext& p,
//         const RGSWCiphertext<DCRTPoly>& A
//     ) {
//         // DEBUG_TIMER("EvalMultPlain RGSW");

//         const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
//         if (!cp)
//             throw std::runtime_error("EvalMultPlain: cryptoparams not RNS");

//         const auto paramsQ    = cp->GetElementParams();
//         const auto paramsQP   = cp->GetParamsQP();
//         const auto& pparamsQP = paramsQP->GetParams();
//         const uint32_t sizeQ  = paramsQ->GetParams().size();
//         const uint32_t sizeQP = paramsQP->GetParams().size();

//         if (!p->Encode())
//             throw std::runtime_error("EvalMultPlain: failed to encode plaintext");
//         DCRTPoly pQ = p->GetElement<DCRTPoly>();
//         pQ.SetFormat(Format::EVALUATION);

//         DCRTPoly pQP(paramsQP, Format::EVALUATION, true);
//         for (uint32_t i = 0; i < sizeQ; ++i) {
//             pQP.SetElementAtIndex(i, pQ.GetElementAtIndex(i));
//         }
//         auto p0 = pQ.GetElementAtIndex(0);
//         p0.SetFormat(Format::COEFFICIENT);
//         for (uint32_t i = sizeQ; i < sizeQP; ++i) {
//             auto tmp = p0;
//             tmp.SwitchModulus(pparamsQP[i]->GetModulus(), pparamsQP[i]->GetRootOfUnity(), 0, 0);
//             tmp.SetFormat(Format::EVALUATION);
//             pQP.SetElementAtIndex(i, std::move(tmp));
//         }

//         if (!A.top || !A.bot)
//             throw std::runtime_error("EvalMultPlain: RGSW operand has null top/bot key");

//         const size_t dnum = A.size();
//         auto scaleSide = [&](const EvalKey<DCRTPoly>& side) {
//             const auto& aVec = side->GetAVector();
//             const auto& bVec = side->GetBVector();
//             std::vector<DCRTPoly> outA, outB;
//             outA.reserve(dnum); outB.reserve(dnum);
//             for (size_t j = 0; j < dnum; ++j) {
//                 outA.push_back(aVec[j] * pQP);
//                 outB.push_back(bVec[j] * pQP);
//             }
//             auto out = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(side->GetCryptoContext());
//             out->SetAVector(std::move(outA));
//             out->SetBVector(std::move(outB));
//             return out;
//         };

//         RGSWCiphertext<DCRTPoly> R;
//         R.top = scaleSide(A.top);
//         R.bot = scaleSide(A.bot);
//         return R;
//     }