#pragma once
#include "openfhe.h"

namespace Context {

    // TODO: Un-pollute namespaces
    using namespace lbcrypto;
    using RLWE = Ciphertext<DCRTPoly>;
    using RGSW = std::vector<RLWE>;

/**
 * @brief RGSW-capable crypto context
 * 
 * Uses BV/HPS double decomposition, performing base B digit decomposition one each RNS limb
 */
class BV {
public:
    explicit BVContext(const CryptoContext<DCRTPoly>& cc, const uint32_t ell = 1) 
        : m_params(cc), m_ell(ell), m_logB(computeLogB(cc, ell)), m_powers(computePowers(cc, m_ell, m_logB))
    {
        // DEBUG_PRINT("Q:         " << cc->GetElementParams()->GetModulus());
        // DEBUG_PRINT("# moduli:  " << cc->GetElementParams()->GetParams().size());
        // DEBUG_PRINT("LogB:      " << m_logB << "\n");
    };

public:
    /**
     * @brief Encrypt an RGSW ciphertext of message
     * @note The message can be anything but the noise grows quickly if it is not binary
     * 
     * @param publicKey 
     * @param plaintext 
     * @param noiseless The server does not care about the privacy of the users, so it can use noiseless "encryptions" (public keys)
     * @return RGSW
     */
    RGSW EncryptRGSW(const PublicKey<DCRTPoly>&, const Plaintext&, const bool noiseless = false) const;

    /**
     * @brief Evaluate the external product
     * 
     * @param rlwe 
     * @param rgsw 
     * @return RLWE ciphertext 
     */
    RLWE EvalExternalProduct(const RLWE&, const RGSW&) const;

    /**
     * @brief Evaluate the internal product
     * 
     * @param lhs 
     * @param rhs 
     * @return RGSW 
     */
    RGSW EvalInternalProduct(const RGSW&, const RGSW&) const;

protected:
    const CryptoContext<DCRTPoly>& m_params;
    const uint32_t m_ell;
    const BasicInteger m_logB;
    const std::vector<NativeInteger> m_powers;

    /// @brief Returns calculations of B^i mod q_j
    NativeInteger GetPower(const uint32_t i, const uint32_t j) const {
        return m_powers[i + m_ell * j];
    }

protected:
    /// @brief Returns the input polynomial scaled by B^i as (a, aB, ..., aB^{ell - 1})
    std::vector<DCRTPoly> PowersOfBase(const DCRTPoly& input) const;

    /// @brief Returns the inverse of PowersOfBase
    std::vector<DCRTPoly> Decompose(const DCRTPoly& input) const;

// INIT
private:
    /// @brief Computes B from ell so that ell digits in base B covers max(q_i) 
    static BasicInteger computeLogB(const CryptoContext<DCRTPoly>& cc, const uint32_t ell) {
        const auto& params = cc->GetCryptoParameters()->GetElementParams()->GetParams();
        uint32_t max_msb = 0;
        for (const auto& qi : params) {
            uint32_t msb = qi->GetModulus().GetMSB();
            if (msb > max_msb) max_msb = msb;
        }
        return (max_msb + ell - 1) / ell;
    }
    
    /// @brief Computes B^i mod q_j
    /// @note Most of the factors are the same since each q_i is approx. the same size.
    ///       It might be worth skipping the second dimension (modulo reductions) if space becomes a problem.
    /// @todo The first element B^0 is always 1, consider removing entirely!
    static std::vector<NativeInteger> computePowers(const CryptoContext<DCRTPoly>& cc, const uint32_t ell, const BasicInteger logB) {
        const auto& Q = cc->GetCryptoParameters()->GetElementParams()->GetModulus();
        const auto& q = cc->GetCryptoParameters()->GetElementParams()->GetParams();
        const auto k = q.size();

        std::vector<NativeInteger> powers(ell * k);

        NativeInteger B(BasicInteger(1) << logB);
        NativeInteger cnt = 1;

        for(size_t i = 0; i < ell; i++) {
            for(size_t j = 0; j < k; j++) {
                const auto qj = q[j]->GetModulus();
                powers[i + j*ell] = cnt.Mod(qj);
            }
            
            cnt = cnt.ModMul(B, Q);
        }

        return powers;
    }
    
// HELPER FUNCTIONS
private:
    static bool IsCoefPackedPlaintext(const Plaintext& plaintext) {
        return plaintext->GetEncodingType() == PlaintextEncodings::COEF_PACKED_ENCODING;
    }

    /// @brief Used when the cloned poly should be const except converting to a different format
    static DCRTPoly CloneToCoefficient(const DCRTPoly& plaintext) {
        DCRTPoly clone = plaintext.Clone();
        clone.SetFormat(Format::COEFFICIENT);
        return clone;
    }

// TEST FUNCTIONS (TODO: Remove or move to test)
// PUBLIC_FOR_TEST:
//     DCRTPoly GadgetMultiply(const DCRTPoly& lhs, const DCRTPoly& rhs) const {
//         const auto len = m_params->GetElementParams()->GetParams().size();
//         DCRTPoly sum = DCRTPoly(m_params->GetElementParams(), Format::EVALUATION, true);
//         for(size_t i = 0; i < len; i++) {
//             sum.SetElementAtIndex(i, lhs.GetElementAtIndex(i).Times(rhs.GetElementAtIndex(i)));
//         }
//         return sum;
//     }
};

} // namespace Context