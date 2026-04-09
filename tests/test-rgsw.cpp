#include "core/include/params.h"
#include "core/include/context.h"
#include "math/nbtheory.h"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <iostream>

using namespace core;
using namespace lbcrypto;

void TestA();

int main() {
    TestA();
    return 0;
}

/**
 * @brief returns 2^n
 * @param n the exponent
 * @return 2^n
 */
template <typename T>
constexpr inline T Pow2(T k) {
    return (T(1) << k);
}

/**
 * @brief Generates the indices used in Algorithm 3 of https://eprint.iacr.org/2019/736
 * 
 * @param log_n The number of digits in the binary representation of ...
 */
template <typename T>
constexpr inline std::vector<T> ExpandRLWEIndices(T log_n) {
    std::vector<T> sizes;
    for (uint32_t i = 1; i <= log_n; i++)
        sizes.push_back((T(1) << (log_n - i + 1)) + 1);
    return sizes;
}

/**
 * @brief Algorithm 3 of https://eprint.iacr.org/2019/736
 */
template <typename C, typename T, typename N = uint32_t>
inline std::vector<Ciphertext<T>> ExpandRLWE(
    CryptoContext<C> cc, 
    Ciphertext<T> ct, 
    N log_n,
    std::shared_ptr<std::map<N, lbcrypto::EvalKey<T>>> keyMap
) {
    auto n = N(1) << log_n;
    std::vector<Ciphertext<T>> c(n);
    c[0] = ct;
    
    for(N i = 1; i <= log_n; i++) {
        N k = Pow2(log_n - i + 1) + 1;
        // NOTE: Original paper uses b in [0, 2^i - 1], which is probably meant to be [0, 2^{i - 1}] to not exceed n
        for(N b = 0; b < Pow2(i - 1); b++) {
            auto cb = c[b];
            auto subs = cc->EvalAutomorphism(cb, k, *keyMap);
            auto diff = cc->EvalSub(cb, subs);
            auto sum = cc->EvalAdd(cb, subs);

            auto r = (2 * n - k) % (2 * n);
            std::vector<int64_t> mono(n, 0);
            (r < n) ? (mono[r] = 1) : (mono[r - n] = -1);
            auto ptMono   = cc->MakeCoefPackedPlaintext(mono);
            auto shifted  = cc->EvalMult(diff, ptMono);

            c[2*b] = sum;
            c[2*b + 1] = shifted;
        }
    }

    return c;
}

void TestA() {
    const uint32_t log_n = 3;
    const uint32_t N = 16384; // Smallest recommended value with BGN-rns (l = 4) is 4096

    CCParams<CryptoContextRGSWBGV> params;
    params.SetPlaintextModulus(65537);
    params.SetRingDim(N);
    params.SetMultiplicativeDepth(4);
    // params.SetGadgetBase(2);
    // params.SetGadgetDigits(log_n);

    std::cout << "Created params"<< std::endl;

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::cout << "Created context" << std::endl;

    // Generate k-indices used in Algorithm 3 of https://eprint.iacr.org/2019/736
    auto indices = ExpandRLWEIndices(log_n);
    auto keyMap = cc->EvalAutomorphismKeyGen(keyPair.secretKey, indices);
    std::cout << "Generated indices: " << indices << std::endl;
    
    std::cout << "Created automorphism keys" << std::endl;

    // Encrypt a sample plaintext
    Plaintext plaintext = cc->MakeCoefPackedPlaintext({1, 0, 1});
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    
    std::cout << "Encrypted plaintext " << plaintext << std::endl;

    // Try expanding the ciphertext into an RGSW ciphertext using the generated automorphism keys
    auto rgswCiphertext = ExpandRLWE(cc, ciphertext, log_n, keyMap);
    
    std::cout << "Expanded RLWE" << std::endl;

    // Decrypt the first ciphertext in the expanded RGSW ciphertext and check that it matches the original plaintext
    Plaintext decrypted;
    
    std::cout << "Original plaintext: " << plaintext << std::endl;
    std::cout << "Decrypted plaintext: " << std::endl; 
    
    for(const auto &c : rgswCiphertext) {
        cc->Decrypt(keyPair.secretKey, c, &decrypted);
        decrypted->SetLength(3);
        std::cout << decrypted << std::endl;
    }
}