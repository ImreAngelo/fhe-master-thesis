#include "openfhe.h"

#define DEBUG_LOGGING

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
     * @todo Look into setting ell automatically
     * @todo Look into SIMD operations for constructing (top) rows
     * 
     * @param keys Public/private keys needed
     * @param msg Packed plaintext message to encrypt
     * @param log_B Gadget base power (e.g., 5 gives B = 2^5)
     */
    RGSWCiphertext<DCRTPoly> EncryptRGSW_new(
        const CryptoContext<DCRTPoly>& cc,
        const KeyPair<DCRTPoly>& keys,
        std::vector<int64_t> msg,
        const uint64_t log_B = 5,
        const size_t ell = 9
    ) {
        const auto& params = cc->GetCryptoParameters();

        const auto t = params->GetPlaintextModulus();
        const auto B = (1ULL << log_B);
        
        const auto msgSlots = msg.size();
        
        RGSWCiphertext<DCRTPoly> G(2*ell);
        int64_t gi = 1;

        for (size_t i = 0; i < ell; i++, gi = (gi * B) % t) {
            std::cout << "B^" << i << " = " << gi << " mod " << t << std::endl;

            // Bottom L rows: msg * B^i
            // TODO: Use SIMD for scalar * vector (mod t if possible)
            std::vector<int64_t> row = msg;
            for(size_t j = 0; j < msgSlots; j++) {
                row[j] *= gi;
                row[j] %= t;
            }

            Plaintext mBi = cc->MakePackedPlaintext(row);
            G[i + ell] = cc->Encrypt(keys.secretKey, mBi);
            
            // Top L rows: -s * msg * B^i
            // enc(-s * msg * B^i) = Enc(0) - Enc(msg * B^i)
            // TODO: Confirm identity in main doc, it should follow directly from Z - \mu G with Z = 0!
            auto zeroPt = cc->MakePackedPlaintext(std::vector<int64_t>(msgSlots, 0));
            auto topCt = cc->Encrypt(keys.secretKey, zeroPt);
            if(!mBi->Encode())  // ensure DCRTPoly form is populated
                throw "Error 1";
            auto mBiPoly = mBi->GetElement<DCRTPoly>();

            auto& elems = topCt->GetElements();
            mBiPoly.SetFormat(elems[1].GetFormat());  // match NTT/coeff form of c1
            elems[1] -= mBiPoly;

            G[i] = topCt;
        }
    
    #if defined(DEBUG_LOGGING)
        std::cout << "G: " << std::endl;
        for(const auto& row : G) {
            Plaintext decrytedRow;
            cc->Decrypt(keys.secretKey, row, &decrytedRow);
            decrytedRow->SetLength(msgSlots);
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
        RGSWCiphertext<DCRTPoly> rgsw,
        size_t ell = 4,
        uint64_t B = 2 // TODO: get all params from m_params

    ) {


        return rlwe;
    }
}