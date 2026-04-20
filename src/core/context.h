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
        explicit ExtendedCryptoContextImpl(const CryptoContextImpl<T>& base, const CCParams<CryptoContextRGSWBGV>& params)
            : CryptoContextImpl<T>(base), m_params(params) {}

    public:
        /**
         * @brief Homomorphically evaluate the external product.
         * 
         * @param x 
         * @param Y 
         * @param log_B 
         * @param ell 
         * @return Ciphertext<DCRTPoly> 
         */
        inline Ciphertext<DCRTPoly> EvalExternalProduct(
            const Ciphertext<DCRTPoly>& x,
            const RGSWCiphertext<DCRTPoly>& Y
        ) {
            // TODO: Document GadgetBase is not gadget base, but rather 2^base
            const uint64_t log_B = m_params.GetGadgetBase();
            const size_t ell = m_params.GetGadgetDecomposition();

            // Decompose both ciphertext components in base B.
            // BaseDecompose operates per-limb in RNS — this is correct because
            // ell is chosen to cover the full product modulus (ell = ceil(log_B(q))).
            DCRTPoly b = x->GetElements()[0];
            DCRTPoly a = x->GetElements()[1];
            b.SetFormat(Format::COEFFICIENT);
            a.SetFormat(Format::COEFFICIENT);

            std::vector<DCRTPoly> v = b.BaseDecompose(log_B, true); // digits of b
            std::vector<DCRTPoly> u = a.BaseDecompose(log_B, true); // digits of a

            // auto zero = DCRTPoly(b.GetParams(), Format::EVALUATION, true);
            // v.resize(ell, zero);
            // u.resize(ell, zero);

            if (u.size() != ell || v.size() != ell) {
                std::cout << "Size mismatch: " << u.size() << " / " << ell << ", " << v.size() << " / " << ell << std::endl;
                throw std::runtime_error("BaseDecompose depth mismatch — check ell vs log_B vs q");
            }

            // Accumulate: result = sum_i u[i]*Y[i] + sum_i v[i]*Y[ell+i]
            auto result = ScalarMultCiphertext(Y[0], u[0]);
            for (size_t i = 1; i < ell; i++)
                result = this->EvalAdd(result, ScalarMultCiphertext(Y[i],       u[i]));
            for (size_t i = 0; i < ell; i++)
                result = this->EvalAdd(result, ScalarMultCiphertext(Y[i + ell], v[i]));

            return result;
        }

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
        inline RGSWCiphertext<DCRTPoly> EncryptRGSW(
            const PrivateKey<DCRTPoly>& secretKey,
            std::vector<int64_t> msg
        ) {
            // TODO: Document GadgetBase is not gadget base, but rather 2^base
            const uint64_t log_B = m_params.GetGadgetBase();
            const size_t ell = m_params.GetGadgetDecomposition();
            
            const Plaintext zero   = this->MakePackedPlaintext({ 0 });
            const Plaintext mPlain = this->MakePackedPlaintext(msg);

            if (!mPlain->Encode())
                throw std::runtime_error("Failed to encode plaintext");
            
            RGSWCiphertext<DCRTPoly> G(2 * ell);

            // Scale m by B^i at the R_Q polynomial level (per-tower integer mul),
            // NOT at the R_t plaintext level. Going through MakePackedPlaintext would
            // reduce each slot mod t, introducing a carry polynomial K_i with
            // |K_i| ~ B^i. The external product then produces t·Σv[i]·K_i, which
            // overflows Q and contaminates the result mod t.
            DCRTPoly mScaled = mPlain->GetElement<DCRTPoly>();
            mScaled.SetFormat(Format::EVALUATION);

            const NativeInteger B(1ULL << log_B);

            for (size_t i = 0; i < ell; i++) {
                // Bottom row i+ell: message is m·B^i (injected into c0).
                // c0 + c1·s = t·e + m·B^i
                {
                    auto bot     = this->Encrypt(secretKey, zero);
                    auto& elems  = bot->GetElements();
                    DCRTPoly add = mScaled;
                    add.SetFormat(elems[0].GetFormat());
                    elems[0] += add;
                    G[i + ell] = bot;
                }

                // Top row i: message is m·B^i·s (injected into c1).
                // c0 + c1·s = t·e + m·B^i·s
                {
                    auto top     = this->Encrypt(secretKey, zero);
                    auto& elems  = top->GetElements();
                    DCRTPoly add = mScaled;
                    add.SetFormat(elems[1].GetFormat());
                    elems[1] += add;
                    G[i] = top;
                }

                mScaled *= B;
            }

            return G;
        }

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
        inline RGSWCiphertext<T> ExpandRLWEHoisted(
            const Ciphertext<T>& ciphertext,
            const PublicKey<T>& publicKey,
            const uint32_t len
        ) {
            // const auto len = (uint32_t(1) << m_params.GetGadgetLevels()); // Only works if number of bits is power of 2
            const auto ciphertext_n = this->Encrypt(publicKey, this->MakePackedPlaintext({ 1 }));
            
            RGSWCiphertext<T> c(len);
            c[0] = this->EvalMult(ciphertext, ciphertext_n);
            
            // TODO: Confirm that EvalFastRotation doesn't use secret keys/that all necessary key material is included in serialization
            const auto precomputed = this->EvalFastRotationPrecompute(ciphertext);
            for(uint32_t i = 1; i < len; i++) {
                const auto rotated = this->EvalFastRotation(ciphertext, i, precomputed);
                c[i] = this->EvalMult(rotated, ciphertext_n);
            }

            return c;
        }

        // /**
        //  * @brief Scales
        //  *
        //  * @todo Choose integer size from (cmake) parameter
        //  * @todo Unify integer types
        //  * @todo Optimize
        //  */
        // inline RingGSWCiphertext<T> ScaleToGadgetLevels(Ciphertext<T>& ct) {
        //     const uint32_t ell = m_params.GetGadgetLevels();
        //     const usint B      = m_params.GetGadgetBase();
        //     std::vector<Ciphertext<T>> result(ell);
        //     // TODO: Assert overflow conditions
        //     auto t_int = this->GetCryptoParameters()->GetPlaintextModulus();
        //     auto bound = static_cast<int64_t>(t_int >> 1);
        //     NativeInteger t(t_int);
        //     NativeInteger b(B);
        //     #if defined(ASSERTIONS) && ASSERTIONS == 1
        //     assert(GreatestCommonDivisor(B, t) == 1 && "B and t must be coprime for the modular inverse to exist");
        //     #endif
        //     for (uint32_t k = 0; k < ell; k++) {
        //         // TODO: Optimize; keep Bk outsde the loop and just do Bk = Bk.ModMul(b, t);
        //         NativeInteger Bk(1); for (uint32_t j = 0; j <= k; j++) Bk = Bk.ModMul(b, t);
        //         int64_t Bk_inv = Bk.ModInverse(t).ConvertToInt<uint64_t>();
        //         // Reduce to centered representation [-t/2, t/2] // (TODO: unnecessary!)
        //         if (Bk_inv > bound) Bk_inv -= (bound << 1); // -= t_int
        //         std::vector<int64_t> scalar(ell, Bk_inv);        
        //         auto pt   = this->MakePackedPlaintext(scalar);
        //         result[k] = this->EvalMult(ct, pt);
        //     }
        //     return result;
        // }

    protected:
        /**
         * @brief Helper: multiply each component of an RLWE ciphertext by a scalar polynomial
         * 
         * @param ct 
         * @param scalar 
         * @return 
         */
        inline static Ciphertext<DCRTPoly> ScalarMultCiphertext(
            const Ciphertext<DCRTPoly>& ct,
            const DCRTPoly& scalar
        ) {
            auto result = std::make_shared<CiphertextImpl<DCRTPoly>>(*ct);
            auto& elems = result->GetElements();
            elems[0] *= scalar;
            elems[1] *= scalar;
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