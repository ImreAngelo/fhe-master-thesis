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

    ExtendedCryptoContextImpl::ExtendedCryptoContextImpl(const CryptoContextImpl<DCRTPoly>& base, const CCParams<CryptoContextRGSWBGV>& params)
    : CryptoContextImpl<DCRTPoly>(base), m_params(params), m_gadgetVectorScalars(BV::GadgetScalars(base)), m_gadgetDecompVectorScalars(BV::InverseGadgetScalars(base)) {}

    /// @brief Return RGSW ciphertext
    std::vector<Ciphertext<DCRTPoly>> ExtendedCryptoContextImpl::EncryptRGSW(const Plaintext& plaintext) const
    {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        throw new std::logic_error("Not implemented");
    }

    /// @brief D_Q(a)_i = [a · (Q/q_i)^{-1}]_{q_i}, embedded in tower i (other towers zero).
    std::vector<DCRTPoly> ExtendedCryptoContextImpl::Decompose(const DCRTPoly& a) const {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        const auto q = params->GetElementParams()->GetParams();

        std::vector<DCRTPoly> d;
        d.reserve(q.size());

        for (size_t i = 0; i < q.size(); i++) {
            DCRTPoly di(params->GetElementParams(), a.GetFormat(), true);
            const auto qi = q[i]->GetModulus();
            auto tower = a.GetElementAtIndex(i).Times(m_gadgetDecompVectorScalars[i]).Mod(qi);
            di.SetElementAtIndex(i, tower);
            d.push_back(std::move(di));
        }

        return d;
    }

    /// @brief P_Q(b)_i = [b · (Q/q_i)]_Q. In RNS form only tower i is non-zero.
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
