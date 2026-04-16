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
        sk_poly.SetFormat(Format::EVALUATION); // TODO: probably is evaluation already.. (confirm)
        auto& s = sk_poly.GetElementAtIndex(0);

        // NOTE: code is 0-index, formulas are 1-indexed so i = i + 1
        for (size_t i = 0; i < ell; i++) {
            // Find 1/B^i mod t
            b_ctr = b_ctr.ModMul(B, t);
            gi = b_ctr.ModInverse(t);

            // Bottom L rows: msg/B^i
            std::vector<int64_t> row(ell);
            for(size_t j = 0; j < ell; j++) {
                auto val = gi.ModMul(NativeInteger(msg[j]), t);
                row[j] = val.ConvertToInt<int64_t>();
            }

            Plaintext bottom = cc->MakePackedPlaintext(row);
            G[i + ell] = cc->Encrypt(keys.secretKey, bottom);
            
            // Top L rows: -s * msg/B^i
            for(size_t j = 0; j < ell; j++) {
                auto val = (t - s[j]).ModMul(row[j], t);
                row[j] = val.ConvertToInt<int64_t>();
            }

            Plaintext top = cc->MakePackedPlaintext(row);
            G[i] = cc->Encrypt(keys.secretKey, top);
        }
        
// #define DEBUG_LOGGING
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