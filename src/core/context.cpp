#include "context.h"
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
