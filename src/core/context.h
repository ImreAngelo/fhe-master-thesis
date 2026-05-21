#pragma once

#include "openfhe.h"
#include <vector>

// TODO: Clean up -> common.h or utils
#if defined(TEST_INTERNAL_FUNCTIONS) 
#define PUBLIC_FOR_TEST public
#else
#define PUBLIC_FOR_TEST protected
#endif


namespace Core
{

using namespace lbcrypto;
using RGSW = std::vector<Ciphertext<DCRTPoly>>;

/**
 * @brief RGSW-capable crypto context.
 * 
 * Uses BV/HPS double-layered decomposition.
 */
class HPSContext {
public:
    explicit HPSContext(const CryptoContext<DCRTPoly>& cc, const uint32_t ell = 1) 
        : m_params(cc), m_ell(ell), m_logB(computeLogB(cc, ell)), m_powers(computePowers(cc, m_ell, m_logB))
    {
        DEBUG_PRINT("Q:         " << cc->GetElementParams()->GetModulus());
        DEBUG_PRINT("# moduli:  " << cc->GetElementParams()->GetParams().size());
        DEBUG_PRINT("LogB:      " << m_logB << "\n");
    };

public:
    /**
     * @brief Encrypt an RGSW ciphertext
     * 
     * @param publicKey 
     * @param plaintext 
     * @return std::vector<Ciphertext<DCRTPoly>> 
     */
    std::vector<Ciphertext<DCRTPoly>> Encrypt(const PublicKey<DCRTPoly>& publicKey, const Plaintext& plaintext) const;

    std::vector<Ciphertext<DCRTPoly>> EncryptRGSW(const PublicKey<DCRTPoly>&, const Plaintext&) const;

    /**
     * @brief Evaluate the external product
     * 
     * @param rlwe 
     * @param rgsw 
     * @return Ciphertext<DCRTPoly> 
     */
    Ciphertext<DCRTPoly> EvalExternalProduct(const Ciphertext<DCRTPoly>& rlwe, const std::vector<Ciphertext<DCRTPoly>>& rgsw) const;

    /**
     * @brief Evaluate the internal product
     * 
     * @param lhs 
     * @param rhs 
     * @return RGSW 
     */
    RGSW EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const;

protected:
    const CryptoContext<DCRTPoly>& m_params;
    const uint32_t m_ell;
    const BasicInteger m_logB;

    /// @brief Calculations of B^i mod q_j for i < L and j < k (Barrett reduction)
    const std::vector<NativeInteger> m_powers; // m_powers?

    NativeInteger GetPower(const uint32_t i, const uint32_t tower) const {
        // assert(i < m_ell); // assert(tower < m_params->GetElementParams()->GetParams().size());
        return m_powers[i + m_ell * tower];
    }

protected:
    std::vector<DCRTPoly> PowersOfBase(const DCRTPoly& input) const;


// HELPER FUNCTIONS
private:
    static inline bool IsCoefPackedPlaintext(const Plaintext& plaintext) {
        return plaintext->GetEncodingType() == PlaintextEncodings::COEF_PACKED_ENCODING;
    }

// INIT
private:
    static BasicInteger computeLogB(const CryptoContext<DCRTPoly>& cc, const uint32_t ell) {
        const auto& params = cc->GetCryptoParameters()->GetElementParams()->GetParams();
        uint32_t max_msb = 0;
        for (const auto& qi : params) {
            uint32_t msb = qi->GetModulus().GetMSB();
            if (msb > max_msb) max_msb = msb;
        }
        return (max_msb + ell - 1) / ell;
    }
    
    /// @note Most of the factors are the same since each q_i is approx. the same size.
    ///       It might be worth skipping the second dimension (modulo reductions) if space becomes a problem.
    /// @todo The first element B^0 is always 1, consider removing entirely!
    /// @todo Remove prints in dev mode
    static std::vector<NativeInteger> computePowers(const CryptoContext<DCRTPoly>& cc, const uint32_t ell, const BasicInteger logB) {
        const auto& Q = cc->GetCryptoParameters()->GetElementParams()->GetModulus();
        const auto& q = cc->GetCryptoParameters()->GetElementParams()->GetParams();
        const auto k = q.size();

        std::vector<NativeInteger> powers(ell * k);

        NativeInteger B(BasicInteger(1) << logB);
        NativeInteger cnt = 1;

        std::cout << "\nmoduli "; 
        for(const auto& qi : q) std::cout << std::setw(14) << qi->GetModulus() << " ";
        std::cout << std::endl;

        for(size_t i = 0; i < ell; i++) {
            std::cout << "B^" << i << " = [" << std::setw(14);

            for(size_t j = 0; j < k; j++) {
                const auto qj = q[j]->GetModulus();
                powers[i + j*ell] = cnt.Mod(qj);
                std::cout << std::setw(14) << powers[i + j*ell] << " ";
            }
            std::cout << std::setw(1) << "]" << std::endl;
            
            cnt = cnt.ModMul(B, Q);
        }

        std::cout << std::endl;
        return powers;
    }

// TEST FUNCTIONS
PUBLIC_FOR_TEST:
    DCRTPoly GadgetMultiply(const DCRTPoly& lhs, const DCRTPoly& rhs) const {
        const auto len = m_params->GetElementParams()->GetParams().size();

        DCRTPoly sum = DCRTPoly(m_params->GetElementParams(), Format::EVALUATION, true);
        for(size_t i = 0; i < len; i++) {
            sum.SetElementAtIndex(i, lhs.GetElementAtIndex(i).Times(rhs.GetElementAtIndex(i)));
        }

        return sum;
    }

    /// @todo Assert eval mode
    std::vector<DCRTPoly> Decompose(const DCRTPoly& input) const {
        const auto& q = m_params->GetElementParams()->GetParams();

        DCRTPoly zero(input.GetParams(), Format::EVALUATION, true);
        std::vector<DCRTPoly> d(q.size(), zero);

        for (size_t i = 0; i < q.size(); i++) {
            d[i].SetElementAtIndex(i, input.GetElementAtIndex(i));
        }

        return d;
    }
};


    /**
     * @brief Crypto Context with RGSW operations: encrypt, external and internal products
     * 
     * Uses HYBRID keyswitching gadget
     */
    class ExtendedCryptoContextImpl : public CryptoContextImpl<DCRTPoly> {
    public:
        explicit ExtendedCryptoContextImpl(const CryptoContextImpl<DCRTPoly>&);

    // PUBLIC_FOR_TEST:
        /**
         * @brief Hoisted RLWE expansion (Algorithm 3 of eprint 2019/736).
         *
         * Returns a vector of RLWE ciphertexts where c[i] encrypts the i-th
         * coefficient/slot of the input. Conversion to RGSW is a separate step.
         */
        // std::vector<Ciphertext<DCRTPoly>> ExpandRLWEHoisted(
        //     const Ciphertext<DCRTPoly>& ciphertext,
        //     const PublicKey<DCRTPoly>& publicKey,
        //     const uint32_t len
        // );
    };

    //-------------------------//
    // OpenFHE-Context Factory //
    //-------------------------//
    /// @brief Templated alias kept for call-site compatibility; the impl is DCRTPoly-only, so the parameter is ignored.
    /// @todo Remove poly template from everywhere
    template <typename T = DCRTPoly>
    using ExtendedCryptoContext = std::shared_ptr<ExtendedCryptoContextImpl>;

    template <typename T>
    struct ContextRegistrar : protected CryptoContextFactory<T> {
        static void Register(std::shared_ptr<CryptoContextImpl<T>> cc) {
            CryptoContextFactory<T>::AddContext(cc);
        }
    };

    inline ExtendedCryptoContext<DCRTPoly> GenExtendedCryptoContext(const CCParams<CryptoContextBGVRNS>& params) {
        auto ext = std::make_shared<ExtendedCryptoContextImpl>(*GenCryptoContext(params));
        ContextRegistrar<DCRTPoly>::Register(ext);
        return ext;
    }
}



/// @brief Encrypt with noise 
/// @todo
/*
std::vector<Ciphertext<DCRTPoly>> EncryptReal(
    const CryptoContext<DCRTPoly>& cc, const HybridTables& tables, 
    const PrivateKey<DCRTPoly>& secretKey, const Plaintext& m
) {
    DEBUG_TIMER("Encrypt RGSW");

    const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const auto paramsQP = tables.paramsQP;
    const auto t = params->GetPlaintextModulus();

    DCRTPoly mP = Power(cc, m->GetElement<DCRTPoly>());

    DiscreteGaussianGeneratorImpl<NativeVector> dgg = params->GetDiscreteGaussianGenerator();
    DiscreteUniformGeneratorImpl<NativeVector> dug;

    // Lift secret key s to QP-base
    DCRTPoly s = Decompose(cc, secretKey->GetPrivateElement(), tables);

    std::vector<Ciphertext<DCRTPoly>> rgsw;
    for(size_t i = 0; i < 2; i++) {
        DCRTPoly a(dug, paramsQP, Format::EVALUATION);
        DCRTPoly e(dgg, paramsQP, Format::EVALUATION);

        // BGV Encryption:
        // c1 = a
        // c0 = -(a*s + t*e)
        DCRTPoly c1 = a;
        DCRTPoly c0 = (a * s);
        
        // Add error t*e
        e.Times(NativeInteger(t));
        c0 += e;
        c0 = c0.Negate();

        auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(cc);
        ct->SetElements({std::move(c0), std::move(c1)});
        rgsw.push_back(ct);
    }

    // Add mP to diagonals
    rgsw[0]->GetElements()[0] += mP;
    rgsw[1]->GetElements()[1] += mP;

    return rgsw;
} */

/// @brief External product without mod down QP -> Q
/// @todo Stay in QP basis for as long as possible!
// std::pair<DCRTPoly,DCRTPoly> EvalExternalProductQP(
//     const CryptoContext<DCRTPoly>& cc,
//     const HybridTables& tables,
//     const Ciphertext<DCRTPoly>& rlwe,
//     const std::vector<Ciphertext<DCRTPoly>>& rgsw
// ) {
//     auto c = rlwe->GetElements();
//     c[0].SetFormat(Format::EVALUATION);
//     c[1].SetFormat(Format::EVALUATION);
//     auto d0 = Decompose(cc, c[0], tables);
//     auto d1 = Decompose(cc, c[1], tables);
//     DCRTPoly out0(tables.paramsQP, Format::EVALUATION, true);
//     DCRTPoly out1(tables.paramsQP, Format::EVALUATION, true);
//     out0 += d0 * rgsw[0]->GetElements()[0];
//     out1 += d0 * rgsw[0]->GetElements()[1];
//     out0 += d1 * rgsw[1]->GetElements()[0];
//     out1 += d1 * rgsw[1]->GetElements()[1];
//     return {out0, out1};
// }

