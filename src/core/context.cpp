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
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const auto zero = this->MakePackedPlaintext({0});
        const auto mg = GadgetMul(plaintext->GetElement<DCRTPoly>());

        // TODO: Make work for CoefPackedPlaintext as well
        // zero->SetFormat(plaintext->format) or something
        
        std::vector<Ciphertext<DCRTPoly>> rgsw;
        rgsw.reserve(2*mg.size());

        // auto Z = this->Encrypt(publicKey, zero);
        
        for(size_t col = 0; col < 2; col++) {
            for(const auto& mgi : mg) {
                // auto z = Z->Clone();
                auto z = this->Encrypt(publicKey, zero);
                z->GetElements()[col] += mgi;
                rgsw.push_back(std::move(z));
            }
        }

        return rgsw;
    }

    /// @brief Returns the external product between the rlwe and rgsw
    RLWE ExtendedCryptoContextImpl::EvalExternalProduct(const RLWE &rlwe, const RGSW &rgsw) const
    {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const size_t L = params->GetElementParams()->GetParams().size();

        auto c0 = rlwe->GetElements()[0];
        auto c1 = rlwe->GetElements()[1];
        c0.SetFormat(Format::EVALUATION);
        c1.SetFormat(Format::EVALUATION);

        const auto d0 = Decompose(c0);
        const auto d1 = Decompose(c1);

        DCRTPoly out0(params->GetElementParams(), Format::EVALUATION, true);
        DCRTPoly out1(params->GetElementParams(), Format::EVALUATION, true);
        for (size_t i = 0; i < L; i++) {
            const auto& m0 = rgsw[i]->GetElements();
            const auto& m1 = rgsw[L + i]->GetElements();
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

    /// @brief D_Q(a)_i = [a · (Q/q_i)^{-1}]_{q_i} as a *small* integer polynomial in R,
    ///        embedded consistently across all towers (each tower = the same small poly mod q_k).
    /// This is required for BV-RNS use with encrypted gadget vectors so that noise terms
    /// d_i · e_i remain small integer polynomials when interpreted mod Q.
    std::vector<DCRTPoly> ExtendedCryptoContextImpl::Decompose(const DCRTPoly& a) const {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const auto& q = params->GetElementParams()->GetParams();
        const size_t L = q.size();

        // Need COEFFICIENT form to construct the small integer polynomial.
        DCRTPoly aCoef(a);
        aCoef.SetFormat(Format::COEFFICIENT);

        std::vector<DCRTPoly> d;
        d.reserve(L);

        for (size_t i = 0; i < L; i++) {
            const auto qi = q[i]->GetModulus();
            // small_poly_i = a.tower(i) · (Q/q_i)^{-1} mod q_i  (a NativePoly with values in [0, q_i))
            auto smallPoly = aCoef.GetElementAtIndex(i).Times(m_gadgetDecompVectorScalars[i]).Mod(qi);

            DCRTPoly di(params->GetElementParams(), Format::COEFFICIENT, true);
            for (size_t k = 0; k < L; k++) {
                if (k == i) {
                    di.SetElementAtIndex(k, smallPoly);
                } else {
                    // SwitchModulus interprets `smallPoly` as a centered integer in [-q_i/2, q_i/2]
                    // and reduces it mod q_k, giving the same small poly's residues in tower k.
                    auto tk = smallPoly;
                    tk.SwitchModulus(q[k]->GetModulus(), q[k]->GetRootOfUnity(), 0, 0);
                    di.SetElementAtIndex(k, std::move(tk));
                }
            }
            di.SetFormat(Format::EVALUATION);
            d.push_back(std::move(di));
        }

        return d;
    }

    /// @brief P_Q(b)_i = [b*(Q/q_i)]_Q. In RNS form only tower i is non-zero.
    std::vector<DCRTPoly> ExtendedCryptoContextImpl::GadgetMul(const DCRTPoly& b) const {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const auto q = params->GetElementParams()->GetParams();

        std::vector<DCRTPoly> P;
        P.reserve(q.size());

        for (size_t i = 0; i < q.size(); i++) {
            DCRTPoly Pi(params->GetElementParams(), b.GetFormat(), true);
            const auto qi = q[i]->GetModulus();
            auto tower = b.GetElementAtIndex(i).Times(m_gadgetVectorScalars[i]).Mod(qi);
            Pi.SetElementAtIndex(i, tower);
            P.push_back(std::move(Pi));
        }

        return P;
    }

    /// @brief Unscaled gadget vector g_i = [Q/q_i]_Q (i.e. P_Q(1)).
    /// Useful for verifying the reconstruction identity <D_Q(a), g> ≡ a (mod Q).
    std::vector<DCRTPoly> ExtendedCryptoContextImpl::GadgetVector() const {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const auto q = params->GetElementParams()->GetParams();

        std::vector<DCRTPoly> out;
        out.reserve(q.size());
        for (size_t i = 0; i < q.size(); i++) {
            // Constant polynomial g_i ∈ R_Q: only tower i is non-zero, holding the constant g[i].
            DCRTPoly poly(params->GetElementParams(), Format::COEFFICIENT, true);
            auto tower = poly.GetElementAtIndex(i);
            tower[0] = m_gadgetVectorScalars[i];
            poly.SetElementAtIndex(i, tower);
            poly.SetFormat(Format::EVALUATION);
            out.push_back(std::move(poly));
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
