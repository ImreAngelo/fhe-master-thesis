#pragma once

#include "openfhe.h"
#include "params.h"
#include "rgsw.h"

#include <vector>

namespace Context
{
    using namespace lbcrypto;

    /**
     * @brief BGV-RNS context extended with RGSW-on-hybrid-keyswitch operations.
     *
     * RGSW ciphertexts use the hybrid-keyswitch RNS digit gadget: dnum (a, b)
     * pairs in QP basis, one per Q-partition. External product reuses
     * KeySwitchHYBRID::EvalKeySwitchPrecomputeCore + EvalFastKeySwitchCore.
     */
    template <typename T = DCRTPoly>
    class ExtendedCryptoContextImpl : public CryptoContextImpl<T> {
        CCParams<CryptoContextRGSWBGV> m_params;

    public:
        explicit ExtendedCryptoContextImpl(const CryptoContextImpl<T>& base, const CCParams<CryptoContextRGSWBGV>& params);

    /// @brief Textbook implementations
    public:
        std::vector<Ciphertext<T>> Encrypt_Textbook(
            const PublicKey<T> &publicKey, 
            const Plaintext& plaintext,
            const uint64_t log_B,
            const size_t ell
        );

        Ciphertext<T> EvalExternalProduct_Textbook(
            const Ciphertext<T>& rlwe,
            const std::vector<Ciphertext<T>>& rgsw,
            const uint64_t log_B
        );

        std::vector<Ciphertext<T>> EvalInternalProduct_Textbook(
            const std::vector<Ciphertext<T>>& rgsw_left,
            const std::vector<Ciphertext<T>>& rgsw_right,
            const uint64_t log_B
        );

    /// @brief RNS-implementation
    public:
        /**
         * @brief Homomorphic external product: RLWE × RGSW → RLWE.
         */
        Ciphertext<DCRTPoly> EvalExternalProduct(
            const Ciphertext<DCRTPoly>& x,
            const RGSWCiphertext<DCRTPoly>& Y
        );

        /**
         * @brief Homomorphic internal product: RGSW × RGSW → RGSW.
         */
        RGSWCiphertext<DCRTPoly> EvalInternalProduct(
            const RGSWCiphertext<DCRTPoly>& left,
            const RGSWCiphertext<DCRTPoly>& right
        );

        /**
         * @brief Hybrid internal product: RGSW × RGSW → RGSW.
         *
         * Textbook decomposition (one external product per gadget row of B)
         * built on top of the RNS external-product kernel. Each row of B is
         * projected QP→Q via ApproxModDown, fed through EvalExternalProduct
         * against A, and the resulting Q-basis RLWEs are repacked into a
         * fresh QP-basis RGSW (multiplying by P in Q-side, zero P-side).
         *
         * Slower per-call than EvalInternalProduct (2·dnum external products
         * vs. dnum-row dot product) but doesn't accumulate the QP-residue
         * noise that breaks chained EvalInternalProduct calls.
         */
        RGSWCiphertext<DCRTPoly> EvalInternalProduct_Hybrid(
            const RGSWCiphertext<DCRTPoly>& left,
            const RGSWCiphertext<DCRTPoly>& right
        );

        /**
         * @brief Element-wise add/sub of two RGSW ciphertexts (operates in QP).
         */
        RGSWCiphertext<DCRTPoly> EvalAddRGSW(
            const RGSWCiphertext<DCRTPoly>& A,
            const RGSWCiphertext<DCRTPoly>& B
        );
        RGSWCiphertext<DCRTPoly> EvalSubRGSW(
            const RGSWCiphertext<DCRTPoly>& A,
            const RGSWCiphertext<DCRTPoly>& B
        );

        /**
         * @brief Plaintext × RGSW: scale every (a, b) row by the plaintext.
         *
         * The plaintext is encoded in Q and lifted to QP (P-side via
         * SwitchModulus on each P-tower, mirroring how `sExt` is built in
         * EncryptRGSW). Linearity gives RGSW(p · m) from RGSW(m), at the cost
         * of one multiplicative level.
         */
        RGSWCiphertext<DCRTPoly> EvalMultPlain(
            const Plaintext& p,
            const RGSWCiphertext<DCRTPoly>& A
        );

        /**
         * @brief Encrypt message as RGSW ciphertext (dnum (a,b) pairs per side, in QP).
         *
         * Mirrors KeySwitchHYBRID::KeySwitchGenInternal: m plays the role of s_old.
         * Requires the secret key.
         */
        RGSWCiphertext<DCRTPoly> EncryptRGSW(
            const PrivateKey<DCRTPoly>& secretKey,
            const Plaintext& plaintext
        );

        /**
         * @brief Decrypt a single (a, b) row of an RGSW ciphertext.
         *
         * Projects (a, b) from QP back to Q via ApproxModDown (which cancels the P
         * factor in the gadget), then decrypts as a regular BGV ciphertext.
         * Test/debug only.
         */
        Plaintext DecryptRGSWRow(
            const PrivateKey<DCRTPoly>& secretKey,
            const DCRTPoly& a,
            const DCRTPoly& b
        );

#if !defined(TEST_INTERNAL_FUNCTIONS)
    protected:
#endif
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

    protected:
        /**
         * @brief ApproxModDown a single QP-basis DCRTPoly back to Ql, using BGV's t-aware variant.
         */
        DCRTPoly ApproxModDownToQ(
            const DCRTPoly& xQP,
            const std::shared_ptr<typename DCRTPoly::Params>& paramsQl
        ) const;
    };

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
