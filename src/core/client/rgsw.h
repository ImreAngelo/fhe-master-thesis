#include "openfhe.h"

namespace Client {
    using namespace lbcrypto;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

// #if !defined(TEST_INTERNAL_FUNCTIONS)
//  protected: 
// #endif
    /**
     * @brief Encrypt message as RGSW ciphertext
     * 
     * @todo Look into SIMD operations for constructing (top) rows
     * 
     * @param keys Public/private keys needed
     * @param msg Packed plaintext message to encrypt
     * @param B Gadget base (default 2)
     */
    RGSWCiphertext<DCRTPoly> EncryptRGSW(
        CryptoContext<DCRTPoly>& cc,
        KeyPair<DCRTPoly>& keys,
        std::vector<int64_t> msg,
        uint64_t B = 2 // todo: create tests for different bases
    ) {
        auto t = NativeInteger(cc->GetCryptoParameters()->GetPlaintextModulus());
        auto ell = msg.size();
        
        RGSWCiphertext<DCRTPoly> G(2*ell);
        NativeInteger b_ctr(1), gi;

        Plaintext zero = cc->MakePackedPlaintext({ 0 });

        // Extract secret s
        // Elements of RLWE is represented as (b, a) so s = element[0]
        auto sk_poly = keys.secretKey->GetPrivateElement();
        sk_poly.SetFormat(Format::EVALUATION);
        auto& s = sk_poly.GetElementAtIndex(0);

        for (size_t i = 0; i < ell; i++) {
            // Find 1/B^{i + 1} mod t
            b_ctr = b_ctr.ModMul(B, t);
            gi = b_ctr.ModInverse(t);
            
            // First L rows
            std::vector<int64_t> mu;
            mu.reserve(ell);

            // -s * msg / B^i = -msg * s/B^i
            // NOTE: in the formula i is 1-index
            for(size_t j = 0; j < ell; j++) {
                auto neg = (msg[j] > 0) ? t - NativeInteger(msg[j]) : NativeInteger(msg[j]);
                auto muj = s[j].ModMul(neg, t).ModMul(gi, t);

                auto mujint = muj.ConvertToInt<uint64_t>();
                // assert(...); // TODO: Check overflow etc. in conversion to signed
                mu.emplace_back(static_cast<int64_t>(mujint));
            }

            Plaintext row_i = cc->MakePackedPlaintext(mu);
            G[i] = cc->Encrypt(keys.secretKey, row_i);

            // Last L rows
            auto b_int = static_cast<int64_t>(gi.ConvertToInt<uint64_t>());
            
            for(size_t j = 0; j < ell; j++) {
                mu[j] = b_int * msg[j];
            }

            Plaintext row_il = cc->MakePackedPlaintext(mu);
            G[i + ell] = cc->Encrypt(keys.secretKey, row_il);
        }
        
#if defined(DEBUG_LOGGING)
        std::cout << "G: " << std::endl;
        for(const auto& row : G) {
            Plaintext decrytedRow;
            cc->Decrypt(keys.secretKey, row, &decrytedRow);
            decrytedRow->SetLength(ell);
            std::cout << decrytedRow << std::endl;
        }
#endif

        return G;
    }
}

namespace Server {
    using namespace lbcrypto;
    
    template <typename T>
    using RLWECiphertext = Ciphertext<T>;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

    /**
     * @brief Evaluate external product homomorphically
     */
    Ciphertext<DCRTPoly> EvalExternalProduct(
        CryptoContext<DCRTPoly>& cc,
        PublicKey<DCRTPoly>& publicKey,
        RLWECiphertext<DCRTPoly> rlwe,
        RGSWCiphertext<DCRTPoly> rgsw
    ) {
        return rlwe;
    }
}