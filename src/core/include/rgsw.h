#include <vector>
#include "openfhe.h"

namespace core::server {
    using namespace lbcrypto;
    
    /**
     * @brief Algorithm 3 of https://eprint.iacr.org/2019/736
     * 
     * @todo Make part of ExtendedCryptoContext<T>
     */
    template <typename T>
    inline std::vector<Ciphertext<T>> ExpandRLWE(
        CryptoContext<T> cc,
        Ciphertext<T> ciphertext,
        uint32_t n,
        PublicKey<T> publicKey
    ) {
        auto ciphertext_n = cc->Encrypt(publicKey, cc->MakePackedPlaintext({ n }));
        
        std::vector<Ciphertext<T>> c(n);
        c[0] = cc->EvalMult(ciphertext, ciphertext_n);
        
        // TODO: Confirm that this doesn't use secret keys
        auto precomputed = cc->EvalFastRotationPrecompute(ciphertext);
        for(uint32_t i = 1; i < n; i++) {
            auto rotated = cc->EvalFastRotation(ciphertext, i, precomputed);
            c[i] = cc->EvalMult(rotated, ciphertext_n);
        }

        return c;
    }
}