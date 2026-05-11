#pragma once

#include "openfhe.h"
#include <vector>

// TODO: Clean up -> common.h or utils
#if defined(TEST_INTERNAL_FUNCTIONS) 
#define PUBLIC_FOR_TEST public
#else
#define PUBLIC_FOR_TEST protected
#endif

namespace Context
{
    using namespace lbcrypto;

    /**
     * @brief Crypto Context with RGSW operations: encrypt, external and internal products
     * 
     * Uses HYBRID keyswitching gadget
     */
    class ExtendedCryptoContextImpl : public CryptoContextImpl<DCRTPoly> {
    public:
        explicit ExtendedCryptoContextImpl(const CryptoContextImpl<DCRTPoly>&);

        /// @todo Make wrapper cc->Encrypt(sk, pt, RLWE or RGSW);
        std::vector<Ciphertext<DCRTPoly>> EncryptRGSW(const PublicKey<DCRTPoly>&, const Plaintext&) const;
        
        /// @brief External product
        Ciphertext<DCRTPoly> EvalExternalProduct(const Ciphertext<DCRTPoly>& rlwe, const std::vector<Ciphertext<DCRTPoly>>& rgsw) const;
        
        /// @brief Internal product
        std::vector<Ciphertext<DCRTPoly>> EvalInternalProduct(const std::vector<Ciphertext<DCRTPoly>>& lhs, const std::vector<Ciphertext<DCRTPoly>>& rhs) const;
        
    protected:
        // TODO: Make const
        std::shared_ptr<CryptoParametersRNS> m_params;
        std::vector<std::vector<NativeInteger>> m_qHatModP;
        std::vector<NativeInteger> m_qInv;
        std::vector<NativeInteger> pInvModq;

        static void GenerateTables();

    PUBLIC_FOR_TEST:
        /// @brief Thin wrapper around OpenFHE's ApproxModDown (QP -> Q)
        DCRTPoly ApproxModDown(const DCRTPoly&) const;

        /// @brief Scale Q -> QP
        DCRTPoly Power(const DCRTPoly&) const;
        
        /// @brief Decompose QP -> Q
        DCRTPoly Decompose(const DCRTPoly&) const;

        // /// @brief Hybrid decomposition with more than 1 digit
        // std::vector<DCRTPoly> HybridDecompose(const DCRTPoly&, uint32_t alpha) const;

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

