#pragma once

#include "openfhe.h"
#include "params.h"
#include "rgsw.h"

#include <vector>

// modinv // todo: include only necessary parts?
// #include "math/nbtheory.h"

namespace Context
{
    using namespace lbcrypto;

    /**
     * @brief Actual implementation of ExtendedCryptoContext
     */
    template <typename T = DCRTPoly>
    class ExtendedCryptoContextImpl : public CryptoContextImpl<T> {
        CCParams<CryptoContextRGSWBGV> m_params;

    public:
        explicit ExtendedCryptoContextImpl(const CryptoContextImpl<T>& base, const CCParams<CryptoContextRGSWBGV>& params);

    public:
        /**
         * @brief Homomorphically evaluate the external product.
         *
         * @param x RLWE ciphertext
         * @param Y RGSW ciphertext
         * @return RLWE ciphertext
         */
        Ciphertext<DCRTPoly> EvalExternalProduct(
            const Ciphertext<DCRTPoly>& x,
            const RGSWCiphertext<DCRTPoly>& Y
        );

        /**
         * @brief Encrypt message as RGSW ciphertext.
         *
         * Only used by tests.
         *
         * @todo Optimize: EncryptBatch and/or construct b in top row directly
         * @todo Set noise scale for each row automatically
         * @todo Set ell automatically
         * @todo Look into SIMD operations for constructing (top) rows
         * @todo Make generic T instead of DCRTPoly
         *
         * @param secretKey Private keys needed
         * @param msg Packed plaintext message to encrypt // TODO: Make const
         * @param log_B Gadget base power (e.g., 5 gives B = 2^5)
         */
        RGSWCiphertext<DCRTPoly> EncryptRGSW(
            const PrivateKey<DCRTPoly>& secretKey,
            std::vector<int64_t> msg
        );

#if !defined(TEST_INTERNAL_FUNCTIONS)
    // only used by HomExpand *and tests*
    protected:
#endif
        /**
         * @brief Takes an RLWE encryption with l slots and converts it to l RLWE ciphertexts,
         * where ciphertext c[i] encrypts b[i]
         *
         * We do not need to account for the scaling being 1/n * B^{-(k + 1)}, we can assume
         * natively the scaling is b^{-(k + 1)}
         *
         * Uses EvalFastRotation from https://eprint.iacr.org/2018/244.
         *
         * @param ciphertext RLWE(sum(b[i] X^i) for 0 <= i < len)
         * @param publicKey The public key
         */
        RGSWCiphertext<T> ExpandRLWEHoisted(
            const Ciphertext<T>& ciphertext,
            const PublicKey<T>& publicKey,
            const uint32_t len
        );

        // /**
        //  * @brief Scales
        //  *
        //  * @todo Choose integer size from (cmake) parameter
        //  * @todo Unify integer types
        //  * @todo Optimize
        //  */
        // RingGSWCiphertext<T> ScaleToGadgetLevels(Ciphertext<T>& ct);

    protected:
        /**
         * @brief Helper: multiply each component of an RLWE ciphertext by a scalar polynomial
         *
         * @param ct
         * @param scalar
         * @return
         */
        static Ciphertext<DCRTPoly> ScalarMultCiphertext(
            const Ciphertext<DCRTPoly>& ct,
            const DCRTPoly& scalar
        );
    };

    /**
     * @brief Extends CryptoContext to contain RGSW functionality required for sPAR optimizations.
     */
    template <typename T>
    using ExtendedCryptoContext = std::shared_ptr<ExtendedCryptoContextImpl<T>>;

    /**
     * @brief Access broker that exposes CryptoContextFactory::AddContext (protected) so we
     * can register our copy-constructed ExtendedCryptoContextImpl with OpenFHE's static
     * context registry (needed for GetContextForPointer to resolve correctly).
     */
    template <typename T>
    struct ContextRegistrar : protected CryptoContextFactory<T> {
        static void Register(std::shared_ptr<CryptoContextImpl<T>> cc) {
            CryptoContextFactory<T>::AddContext(cc);
        }
    };

    /**
     * @brief Constructs an ExtendedCryptoContext from CCParams<CryptoContextRGSWBGV>, mirroring GenCryptoContext.
     *
     * Internally calls GenCryptoContext, copy-constructs an ExtendedCryptoContextImpl from
     * the result, then registers the new object with OpenFHE's context registry so that
     * operations like KeyGen/Encrypt/EvalMult resolve back to the right context.
     */
    inline ExtendedCryptoContext<DCRTPoly> GenExtendedCryptoContext(const CCParams<CryptoContextRGSWBGV>& params) {
        auto ext = std::make_shared<ExtendedCryptoContextImpl<DCRTPoly>>(
            *GenCryptoContext(static_cast<const CCParams<CryptoContextBGVRNS>&>(params)), params);
        ContextRegistrar<DCRTPoly>::Register(ext);
        return ext;
    }
}
