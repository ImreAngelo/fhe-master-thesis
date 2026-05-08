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
    template <typename T = DCRTPoly>
    class ExtendedCryptoContextImpl : public CryptoContextImpl<T> {
        CCParams<CryptoContextRGSWBGV> m_params;

    public:
        explicit ExtendedCryptoContextImpl(const CryptoContextImpl<T>& base, const CCParams<CryptoContextRGSWBGV>& params);

    /// @brief BV-RNS implementations
    protected:
        const std::vector<NativeInteger> m_gadgetVectorScalars;
        const std::vector<NativeInteger> m_gadgetDecompVectorScalars;

    PUBLIC_FOR_TEST:
        /**
         * @brief 
         * 
         * @param a 
         * @return std::vector<DCRTPoly> 
         */
        std::vector<T> Decompose(const T& a) const; 

        /**
         * @brief 
         * 
         * @param b 
         * @return std::vector<DCRTPoly> 
         */
        std::vector<T> GadgetMul(const T& b) const;

        /**
         * @brief 
         * 
         * @return std::vector<DCRTPoly> 
         */
        std::vector<T> GadgetVector() const;


    PUBLIC_FOR_TEST:
        /**
         * @brief Hoisted RLWE expansion (Algorithm 3 of eprint 2019/736).
         *
         * Returns a vector of RLWE ciphertexts where c[i] encrypts the i-th
         * coefficient/slot of the input. Conversion to RGSW is a separate step.
         */
        std::vector<Ciphertext<T>> ExpandRLWEHoisted(
            const Ciphertext<T>& ciphertext,
            const PublicKey<T>& publicKey,
            const uint32_t len
        );
    };

    //-------------------------//
    // OpenFHE-Context Factory //
    //-------------------------//
    template <typename T>
    using ExtendedCryptoContext = std::shared_ptr<ExtendedCryptoContextImpl<T>>;

    template <typename T>
    struct ContextRegistrar : protected CryptoContextFactory<T> {
        static void Register(std::shared_ptr<CryptoContextImpl<T>> cc) {
            CryptoContextFactory<T>::AddContext(cc);
        }
    };

    inline ExtendedCryptoContext<DCRTPoly> GenExtendedCryptoContext(const CCParams<CryptoContextRGSWBGV>& params) {
        auto ext = std::make_shared<ExtendedCryptoContextImpl<DCRTPoly>>(
            *GenCryptoContext(static_cast<const CCParams<CryptoContextBGVRNS>&>(params)), params);
        ContextRegistrar<DCRTPoly>::Register(ext);
        return ext;
    }
}
