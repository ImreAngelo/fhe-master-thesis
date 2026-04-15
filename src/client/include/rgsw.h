#include "openfhe.h"

namespace Client {
    using namespace lbcrypto;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

// protected:
    /**
     * @brief Encrypt RGSW
     * 
     * @param msg Packed plaintext message to encrypt
     * @param B Gadget base (default 2)
     */
    void EncryptRGSW(
        CryptoContext<DCRTPoly>& cc,
        KeyPair<DCRTPoly>& keys,
        std::vector<int64_t> msg,
        // uint32_t ell,       // length
        uint64_t B = 2      // todo: create test for different bases
    ) {
        uint32_t ell = msg.size();
        // uint32_t N = cc->GetRingDimension();
        auto t = NativeInteger(cc->GetCryptoParameters()->GetPlaintextModulus());
        
        RGSWCiphertext<DCRTPoly> G(2*ell);
        NativeInteger b_ctr(1), gi;

        Plaintext zero = cc->MakePackedPlaintext({ 0 });

        // Extract secret s
        // Elements of RLWE is represented as (b, a) so s = element[0]
        auto sk_poly = keys.secretKey->GetPrivateElement();
        sk_poly.SetFormat(Format::EVALUATION);
        auto& s = sk_poly.GetElementAtIndex(0);

        for (uint32_t i = 0; i < ell; i++) {
            // Find 1/B^{i + 1} mod t
            b_ctr = b_ctr.ModMul(B, t);
            gi = b_ctr.ModInverse(t);
            
            // First L rows
            std::vector<int64_t> mu;
            mu.reserve(ell);

            // -s * msg / B^i = -msg * s/B^i
            // NOTE: where i is 1-index
            for(uint32_t j = 0; j < ell; j++) {
                auto neg = (msg[j] > 0) ? t - NativeInteger(msg[j]) : NativeInteger(msg[j]);
                auto muj = s[j].ModMul(neg, t).ModMul(gi, t);

                // TODO: assert check overflow?
                auto mujint = muj.ConvertToInt<uint64_t>();
                mu.emplace_back(static_cast<int64_t>(mujint));
            }

            std::cout << "Row " << i << ": " << mu << std::endl;

            Plaintext row_i = cc->MakePackedPlaintext(mu);
            G[i] = cc->Encrypt(keys.secretKey, row_i);

            // Last L rows
            auto b_int = static_cast<int64_t>(gi.ConvertToInt<uint64_t>());
            
            for(uint32_t j = 0; j < ell; j++) {
                mu[j] = b_int * msg[j];
            }

            Plaintext row_il = cc->MakePackedPlaintext(mu);
            G[i + ell] = cc->Encrypt(keys.secretKey, row_il);
        }
        

        std::cout << "G: " << std::endl;
        for(const auto& row : G) {
            Plaintext decrytedRow;
            cc->Decrypt(keys.secretKey, row, &decrytedRow);
            decrytedRow->SetLength(ell);
            std::cout << decrytedRow << std::endl;
        }
    }

}