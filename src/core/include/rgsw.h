#include <vector>
#include "openfhe.h"

namespace core::server {
    using namespace lbcrypto;
    
    /**
     * @brief EvalFastRotation from https://eprint.iacr.org/2018/244
     * 
     * @todo Make part of ExtendedCryptoContext<T>
     */
    template <typename T>
    inline std::vector<Ciphertext<T>> HoistedExpandRLWE(
        CryptoContext<T> cc,
        Ciphertext<T> ciphertext,
        uint32_t n,
        PublicKey<T> publicKey
    ) {
        auto ciphertext_n = cc->Encrypt(publicKey, cc->MakePackedPlaintext({ n }));
        
        std::vector<Ciphertext<T>> c(n);
        c[0] = cc->EvalMult(ciphertext, ciphertext_n);
        
        // TODO: Confirm that this doesn't use secret keys/that all necessary key material is included in serialization
        auto precomputed = cc->EvalFastRotationPrecompute(ciphertext);
        for(uint32_t i = 1; i < n; i++) {
            auto rotated = cc->EvalFastRotation(ciphertext, i, precomputed);
            // We do not need to account for the scaling being 1/n * B^{-(k + 1)}, we can assume natively the scaling is b^{-(k + 1)}
            // c[i] = cc->EvalMult(rotated, ciphertext_n);
        }

        return c;
    }
}