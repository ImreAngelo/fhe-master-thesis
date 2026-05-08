#pragma once

#include "openfhe.h"
#include "params.h"
#include "rgsw.h"

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
     * @brief BGV-RNS context extended with RGSW operations.
     *
     * Uses BV-RNS gadgets, one for each RNS prime.
     */
    class ExtendedCryptoContextImpl : public CryptoContextImpl<DCRTPoly> {
    public:
        explicit ExtendedCryptoContextImpl(const CryptoContextImpl<DCRTPoly>& base);

        std::vector<Ciphertext<DCRTPoly>> EncryptRGSW(const Plaintext& plaintext) const;

    protected:
        const std::vector<NativeInteger> m_gadgetVectorScalars;
        const std::vector<NativeInteger> m_gadgetDecompVectorScalars;

    PUBLIC_FOR_TEST:
        std::vector<DCRTPoly> Decompose(const DCRTPoly& a) const;
        std::vector<DCRTPoly> GadgetMul(const DCRTPoly& b) const;
        std::vector<DCRTPoly> GadgetVector() const;


    PUBLIC_FOR_TEST:
        /**
         * @brief Hoisted RLWE expansion (Algorithm 3 of eprint 2019/736).
         *
         * Returns a vector of RLWE ciphertexts where c[i] encrypts the i-th
         * coefficient/slot of the input. Conversion to RGSW is a separate step.
         */
        std::vector<Ciphertext<DCRTPoly>> ExpandRLWEHoisted(
            const Ciphertext<DCRTPoly>& ciphertext,
            const PublicKey<DCRTPoly>& publicKey,
            const uint32_t len
        );
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
