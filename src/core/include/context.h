#include <vector>
#include "openfhe.h"

// modinv // todo: include only necessary parts?
// #include "math/nbtheory.h"

namespace Server {
    using namespace lbcrypto;

    template <typename T>
    using RingGSWCiphertext = std::vector<Ciphertext<T>>;

    /**
     * @brief Actual implementation of ExtendedCryptoContext
     */
    template <typename T>
    class ExtendedCryptoContextImpl : public CryptoContextImpl<T> {
    public:
        explicit ExtendedCryptoContextImpl(const CryptoContextImpl<T>& base)
            : CryptoContextImpl<T>(base) {}


    // protected: // only used by HomExpand and tests
        /**
         * @brief Takes an RLWE encryption with l slots and converts it to l RLWE ciphertexts,
         * where ciphertext c[i] encrypts b[i]
         * 
         * We do not need to account for the scaling being 1/n * B^{-(k + 1)}, we can assume 
         * natively the scaling is b^{-(k + 1)}
         * 
         * @param ciphertext RLWE(sum(b[i] X^i) for 0 <= i < len)
         * @param publicKey The public key
         * @param len Number of slots
         */
        inline RingGSWCiphertext<T> ExpandRLWEHoisted(
            const Ciphertext<T>& ciphertext,
            const PublicKey<T>& publicKey,
            const uint32_t len // TODO: Maybe make a CCParam?
        ) {
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
         * @todo Optimize
         * 
         * @param B Gadget base (defaults to 2)
         */
        inline RingGSWCiphertext<T> ScaleToGadgetLevels(
            Ciphertext<T>& ct,
            uint32_t ell,
            usint B = 2  // todo: pull from this->GetCryptoParameters()->GetGadgetBase();
        ) {
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
                NativeInteger Bk(1); for (uint32_t j = 0; j <= k; j++) Bk = Bk.ModMul(b, t);
                int64_t Bk_inv = Bk.ModInverse(t).ConvertToInt<uint64_t>();

                // Reduce to centered representation [-t/2, t/2]
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
     *
     * Usage mirrors GenCryptoContext:
     * @code
     *   auto cc = GenExtendedCryptoContext(params);
     *   cc->Enable(PKE);
     *   auto keys = cc->KeyGen();
     *   cc->ExpandRLWEHoisted(ct, keys.publicKey, n);
     * @endcode
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
     * @brief Constructs an ExtendedCryptoContext from CCParams, mirroring GenCryptoContext.
     *
     * Internally calls GenCryptoContext, copy-constructs an ExtendedCryptoContextImpl from
     * the result, then registers the new object with OpenFHE's context registry so that
     * operations like KeyGen/Encrypt/EvalMult resolve back to the right context.
     */
    template <typename P>
    ExtendedCryptoContext<DCRTPoly> GenExtendedCryptoContext(const CCParams<P>& params) {
        auto ext = std::make_shared<ExtendedCryptoContextImpl<DCRTPoly>>(*GenCryptoContext(params));
        ContextRegistrar<DCRTPoly>::Register(ext);
        return ext;
    }
}


namespace core::server {
    using namespace lbcrypto;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

    // /**
    //  * 
    //  */
    // RGSWCiphertext<DCRTPoly> EncryptRGSW(
    //     CryptoContext<DCRTPoly>& cc,
    //     KeyPair<DCRTPoly>& keys,
    //     Plaintext& msg,
    //     uint32_t l,
    //     uint64_t B = 2
    // ) {
    //     uint32_t N = cc->GetRingDimension();
    //     uint64_t t = cc->GetCryptoParameters()->GetPlaintextModulus();
    //     NativeInteger t_nat(t);

    //     assert(msg.size() <= ring_dim);       
    // }

    RGSWCiphertext<DCRTPoly> CreateRGSW_NegS(
        CryptoContext<DCRTPoly>& cc,
        KeyPair<DCRTPoly>& keys,
        uint32_t ell,
        uint64_t B)
    {
        uint32_t ring_dim = cc->GetRingDimension();
        uint64_t t = cc->GetCryptoParameters()->GetPlaintextModulus();
        NativeInteger t_nat(t);

        // Get secret key in EVALUATION format — these ARE the NTT slot values
        auto sk_poly = keys.secretKey->GetPrivateElement();
        sk_poly.SetFormat(Format::EVALUATION);
        auto& sk_eval = sk_poly.GetElementAtIndex(0);  // first RNS limb

        RGSWCiphertext<DCRTPoly> result(2 * ell);

        for (uint32_t k = 0; k < ell; k++) {
            // Compute B^{-(k+1)} mod t
            NativeInteger Bk(1), B_nat(B);
            for (uint32_t j = 0; j <= k; j++)
                Bk = Bk.ModMul(B_nat, t_nat);
            NativeInteger Bk_inv = Bk.ModInverse(t_nat);

            // ── Top half: packed slots = NTT(-s) * B^{-(k+1)} ────────────────
            std::vector<int64_t> neg_s_slots(ring_dim);
            for (uint32_t i = 0; i < ring_dim; i++) {
                NativeInteger v = sk_eval[i];
                // Negate: (-s) mod t
                NativeInteger neg_v = (v == NativeInteger(0))
                    ? NativeInteger(0)
                    : t_nat - v;
                // Scale by B^{-(k+1)}
                NativeInteger scaled = neg_v.ModMul(Bk_inv, t_nat);
                int64_t c = static_cast<int64_t>(scaled.ConvertToInt<uint64_t>());
                if (c > static_cast<int64_t>(t / 2)) c -= static_cast<int64_t>(t);
                neg_s_slots[i] = c;
            }
            auto pt_neg_s = cc->MakePackedPlaintext(neg_s_slots);
            result[k] = cc->Encrypt(keys.publicKey, pt_neg_s);

            // ── Bottom half: NTT(B^{-(k+1)}) = constant vector ───────────────
            int64_t Bk_inv_c = static_cast<int64_t>(Bk_inv.ConvertToInt<uint64_t>());
            if (Bk_inv_c > static_cast<int64_t>(t / 2))
                Bk_inv_c -= static_cast<int64_t>(t);
            // NTT of a constant scalar is that scalar repeated in every slot
            auto pt_one = cc->MakePackedPlaintext(
                std::vector<int64_t>(ring_dim, Bk_inv_c));
            result[k + ell] = cc->Encrypt(keys.publicKey, pt_one);
        }

        return result;
    }
}