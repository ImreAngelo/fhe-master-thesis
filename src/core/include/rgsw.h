#include <vector>
#include "openfhe.h"

// modinv // todo: include only necessary parts?
#include "math/nbtheory.h"

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

    
    /**
     * @todo Choose integer size from (cmake) parameter
     * @todo Optimize
     * 
     * @param B Gadget base (defaults to 2)
     */
    template <typename T>
    std::vector<Ciphertext<T>> ScaleToGadgetLevels(
        CryptoContext<T>& cc,
        Ciphertext<T>& ct,
        uint32_t ell,
        usint B = 2
    ) {
        std::vector<Ciphertext<T>> result(ell);

        // TODO: Assert overflow conditions
        NativeInteger t(cc->GetCryptoParameters()->GetPlaintextModulus());
        NativeInteger b(B);

        #if defined(ASSERTIONS) && ASSERTIONS == 1
        assert(GreatestCommonDivisor(B, t) == 1 && "B and t must be coprime for the modular inverse to exist");
        #endif

        for (uint32_t k = 0; k < ell; k++) {
            NativeInteger Bk(1); for (uint32_t j = 0; j <= k; j++) Bk = Bk.ModMul(b, t);
            int64_t Bk_inv = Bk.ModInverse(t).ConvertToInt<uint64_t>();

            // Reduce to centered representation [-t/2, t/2]
            if (Bk_inv > static_cast<int64_t>(t >> 1))
                Bk_inv -= static_cast<int64_t>(t);

            std::cout << "Level " << k << ": B^k = " << Bk << ", B^{-k} = " << Bk_inv << std::endl;

            std::vector<int64_t> scalar(ell, Bk_inv);        
            auto pt   = cc->MakePackedPlaintext(scalar);
            result[k] = cc->EvalMult(ct, pt);
        }

        return result;
    }
}