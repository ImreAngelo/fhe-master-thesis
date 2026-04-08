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
std::vector<Ciphertext<T>> ExpandRLWE(
    CryptoContext<C> cc, 
    Ciphertext<T> ciphertext, 
    N log_n,
    std::shared_ptr<std::map<N, lbcrypto::EvalKey<T>>> keyMap
) {
    auto n = N(1) << log_n;
    std::vector<Ciphertext<T>> result(n);
    result[0] = ciphertext;
    
    for(N i = 1; i < log_n; i++) {
        N k = (N(1) << (log_n - i + 1)) + 1;
        for(N b = 0; b < (N(1) << i); b++) {
            auto cb = result[b];
            auto subs = cc->EvalAutomorphism(cb, k, *keyMap);
            auto diff = cc->EvalSub(cb, subs);
            auto sum = cc->EvalAdd(cb, subs);

            auto r = (2 * n - k) % (2 * n);
            std::vector<int64_t> mono(n, 0);
            (r < n) ? (mono[r] = 1) : (mono[r - n] = -1);
            auto ptMono   = cc->MakeCoefPackedPlaintext(mono);
            auto shifted  = cc->EvalMult(diff, ptMono);

            result[2*b] = sum;
            result[2*b + 1] = shifted;
        }
    }

    return result;
}

void TestA() {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetPlaintextModulus(65537);
    params.SetMultiplicativeDepth(3);
    params.SetGadgetBase(2);
    params.SetGadgetDigits(4);

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
    auto indices = ExpandRLWEIndices(params.GetGadgetDigits());
    auto keyMap = cc->EvalAutomorphismKeyGen(keyPair.secretKey, indices);
    
    std::cout << "Created automorphism keys" << std::endl;

    // Encrypt a sample plaintext
    Plaintext plaintext = cc->MakeCoefPackedPlaintext({1, 2, 3, 4, 5, 6, 7, 8});
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    
    std::cout << "Encrypted plaintext " << plaintext << std::endl;

    // Try expanding the ciphertext into an RGSW ciphertext using the generated automorphism keys
    auto rgswCiphertext = ExpandRLWE(cc, ciphertext, params.GetGadgetDigits(), keyMap);
    
    std::cout << "Expanded RLWE" << std::endl;

    // Decrypt the first ciphertext in the expanded RGSW ciphertext and check that it matches the original plaintext
    Plaintext decrypted;
    
    std::cout << "Original plaintext: " << plaintext << std::endl;
    std::cout << "Decrypted plaintext: " << std::endl; 
    
    for(const auto &c : rgswCiphertext) {
        cc->Decrypt(keyPair.secretKey, c, &decrypted);
        decrypted->SetLength(8);
        std::cout << decrypted << std::endl;
    }
}