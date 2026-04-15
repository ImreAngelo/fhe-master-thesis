#include <vector>
#include "openfhe.h"
#include "params.h"

// modinv // todo: include only necessary parts?
// #include "math/nbtheory.h"

namespace Server {
    using namespace lbcrypto;

    template <typename T>
    using RingGSWCiphertext = std::vector<Ciphertext<T>>;

    /**
     * @brief Actual implementation of ExtendedCryptoContext
     */
    template <typename T = DCRTPoly>
    class ExtendedCryptoContextImpl : public CryptoContextImpl<T> {
        CCParams<CryptoContextRGSWBGV> m_params;

    public:
        explicit ExtendedCryptoContextImpl(const CryptoContextImpl<T>& base, const CCParams<CryptoContextRGSWBGV>& params)
            : CryptoContextImpl<T>(base), m_params(params) {}

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
        inline RingGSWCiphertext<T> ExpandRLWEHoisted(
            const Ciphertext<T>& ciphertext,
            const PublicKey<T>& publicKey,
            const uint32_t len
        ) {
            // const auto len = (uint32_t(1) << m_params.GetGadgetLevels()); // Only works if number of bits is power of 2
            const auto ciphertext_n = this->Encrypt(publicKey, this->MakePackedPlaintext({ 1 }));
            
            RingGSWCiphertext<T> c(len);
            c[0] = this->EvalMult(ciphertext, ciphertext_n);
            
            // TODO: Confirm that EvalFastRotation doesn't use secret keys/that all necessary key material is included in serialization
            const auto precomputed = this->EvalFastRotationPrecompute(ciphertext);
            for(uint32_t i = 1; i < len; i++) {
                const auto rotated = this->EvalFastRotation(ciphertext, i, precomputed);
                c[i] = this->EvalMult(rotated, ciphertext_n);
            }

            return c;
        }

        /**
         * @brief Scales
         *
         * @todo Choose integer size from (cmake) parameter
         * @todo Unify integer types
         * @todo Optimize
         */
        inline RingGSWCiphertext<T> ScaleToGadgetLevels(Ciphertext<T>& ct) {
            const uint32_t ell = m_params.GetGadgetLevels();
            const usint B      = m_params.GetGadgetBase();

            std::vector<Ciphertext<T>> result(ell);

            // TODO: Assert overflow conditions
            auto t_int = this->GetCryptoParameters()->GetPlaintextModulus();
            auto bound = static_cast<int64_t>(t_int >> 1);

            NativeInteger t(t_int);
            NativeInteger b(B);

            #if defined(ASSERTIONS) && ASSERTIONS == 1
            assert(GreatestCommonDivisor(B, t) == 1 && "B and t must be coprime for the modular inverse to exist");
            #endif

            for (uint32_t k = 0; k < ell; k++) {
                // TODO: Optimize; keep Bk outsde the loop and just do Bk = Bk.ModMul(b, t);
                NativeInteger Bk(1); for (uint32_t j = 0; j <= k; j++) Bk = Bk.ModMul(b, t);
                int64_t Bk_inv = Bk.ModInverse(t).ConvertToInt<uint64_t>();

                // Reduce to centered representation [-t/2, t/2] // (TODO: unnecessary!)
                if (Bk_inv > bound) Bk_inv -= (bound << 1); // -= t_int

                std::vector<int64_t> scalar(ell, Bk_inv);        
                auto pt   = this->MakePackedPlaintext(scalar);
                result[k] = this->EvalMult(ct, pt);
            }

            return result;
        }
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