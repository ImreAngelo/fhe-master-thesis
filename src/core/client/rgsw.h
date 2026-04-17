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
     * @param keys Private keys needed
     * @param msg Packed plaintext message to encrypt
     * @param log_B Gadget base power (e.g., 5 gives B = 2^5)
     */
    RGSWCiphertext<DCRTPoly> EncryptRGSW(
        const CryptoContext<DCRTPoly>& cc,  // TODO: Make ->encryptRGSW member of ClientImpl
        const PrivateKey<DCRTPoly>& secretKey,
        std::vector<int64_t> msg,
        const uint64_t log_B = 5,           // TODO: Make crypto parameter
        const size_t ell = 9                // TODO: Make crypto parameter
    ) {
        const auto t = cc->GetCryptoParameters()->GetPlaintextModulus();
        const auto B = (1ULL << log_B); 
        const auto slots = msg.size();
        
        RGSWCiphertext<DCRTPoly> G(2*ell);
        
        const Plaintext zero = cc->MakePackedPlaintext({ 0 });
        int64_t gi = 1;

        for (size_t i = 0; i < ell; i++, gi = (gi * B) % t) {
            std::cout << "B^" << i << " = " << gi << " mod " << t << std::endl;

            // Bottom L rows: msg * B^i
            // TODO: Use SIMD for scalar * vector (mod t if possible)
            std::vector<int64_t> row = msg;
            for(size_t j = 0; j < slots; j++) {
                row[j] *= gi;
                row[j] %= t;
            }

            Plaintext mBi = cc->MakePackedPlaintext(row);
            G[i + ell] = cc->Encrypt(secretKey, mBi);
            
            // Top L rows: -s * msg * B^i
            // enc(-s * msg * B^i) = Enc(0) - Enc(msg * B^i)
            // TODO: Confirm identity in main doc, it should follow directly from Z - \mu G with Z = RLWE(0)
            auto top = cc->Encrypt(secretKey, zero); // WARN: create *fresh* ciphertext of 0 each iteration 
            
            if(!mBi->Encode()) // ensure DCRTPoly form is populated
                throw std::runtime_error("mBi is not DCRTPoly");

            auto mBiPoly = mBi->GetElement<DCRTPoly>();

            auto& elems = top->GetElements();
            mBiPoly.SetFormat(elems[1].GetFormat());  // match NTT/coeff form of c1
            elems[1] -= mBiPoly;

            G[i] = top;
        }
    
    #if defined(DEBUG_LOGGING)
        std::cout << "G: " << std::endl;
        for(const auto& row : G) {
            Plaintext decrytedRow;
            cc->Decrypt(secretKey, row, &decrytedRow);
            decrytedRow->SetLength(slots);
            std::cout << decrytedRow << std::endl;

            // TODO: Assert bottom rows are correct (in test)
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