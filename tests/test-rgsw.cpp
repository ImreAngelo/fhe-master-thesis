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
void BFVrnsEvalRotate2n();

int main() {
    // BFVrnsEvalRotate2n();
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

template <typename T>
constexpr inline T Log2(T n) {
    T k = 0;
    while ((T(1) << k) < n) {
        k++;
    }
    return k;
}

/**
 * @brief Generates the indices used in Algorithm 3 of https://eprint.iacr.org/2019/736
 * 
 * @param log_n The number of digits in the binary representation of ...
 */
template <typename T>
constexpr inline std::vector<T> ExpandRLWEIndices(T log_n) {
    std::vector<T> sizes;
    for (uint32_t i = 0; i < log_n; i++)
        sizes.push_back(Pow2(log_n - i) + 1);
    return sizes;
}

// /**
//  * @brief Algorithm 3 of https://eprint.iacr.org/2019/736
//  * 
//  * @param cc the crypto context
//  * @param ct the ciphertext to expand
//  * @param log_n the number of digits in the binary representation of n, where n is
//  * the number of ciphertexts in the output RGSW ciphertext
//  * @param keyMap the evaluation keys for the automorphisms index k
//  * @returns a vector of ciphertexts c[i] that encrypt n * ct[i]
//  */
// template <typename T, typename N = uint32_t>
// inline std::vector<Ciphertext<T>> ExpandRLWE(
//     CryptoContext<T> cc, 
//     Ciphertext<T> ct, 
//     N log_n,
//     std::shared_ptr<std::map<N, lbcrypto::EvalKey<T>>> keyMap,
//     KeyPair<T> keys // DEBUG
// ) {
//     auto n = N(1) << log_n;
//     std::vector<Ciphertext<T>> c(n);
//     c[0] = ct;
    
//     for(N i = 0; i < log_n; i++) {
//         N k = Pow2(log_n - i) + 1;
//         std::cout << "i: " << i << ", k: " << k << std::endl;
//         std::cout << "[0," << Pow2(i) - 1 << "]" << std::endl;

//         // NOTE: Original paper uses b in [0, 2^i - 1], which is probably meant to be [0, 2^{i - 1} - 1] to not exceed n
//         //       We also 0-index i, so we do not need to subtract 1
//         for(N b = 0; b < Pow2(i); b++) {
//             auto cb = c[b];

//             Plaintext debug_cb;
//             cc->Decrypt(keys.secretKey, cb, &debug_cb);
//             debug_cb->SetLength(n * k);
//             std::cout << "cb: " << debug_cb << std::endl;

//             auto subs = cc->EvalAutomorphism(cb, k, *keyMap);
//             auto sum = cc->EvalAdd(cb, subs);
//             auto diff = cc->EvalSub(cb, subs);
            
//             // Multiply by X^{-k}
//             // NOTE: Paper is missing opening paranthesis
//             auto shifted      = cc->EvalRotate(diff, 1);
            
//             // Debugging
//             Plaintext debug_shifted, debug_diff, debug_subs;
//             cc->Decrypt(keys.secretKey, subs, &debug_subs);
//             cc->Decrypt(keys.secretKey, diff, &debug_diff);
//             cc->Decrypt(keys.secretKey, shifted, &debug_shifted);
//             debug_subs->SetLength(n * k);
//             debug_diff->SetLength(n * k);
//             debug_shifted->SetLength(n * k);
//             std::cout << "Subs (k = " << k << "): " << debug_subs << std::endl;
//             std::cout << "Diff: " << debug_diff << std::endl;
//             std::cout << "Shifted: " << debug_shifted << std::endl;

//             // Update
//             c[2*b] = sum;
//             c[2*b + 1] = shifted;

//             // Debugging
//             Plaintext debug_2b, debug_2b1;
//             cc->Decrypt(keys.secretKey, c[2*b], &debug_2b);
//             cc->Decrypt(keys.secretKey, c[2*b + 1], &debug_2b1);
//             debug_2b->SetLength(log_n * k);
//             debug_2b1->SetLength(log_n * k);
//             std::cout << "Intermediary [" << 2*b << "]:\t" << debug_2b << std::endl;
//             std::cout << "Intermediary [" << 2*b + 1 << "]:\t" << debug_2b1 << std::endl;
//         }
//     }

//     return c;
// }

/**
 * @brief Alg 3????
 */
inline std::vector<Ciphertext<DCRTPoly>> ExpandRLWENaive(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ciphertext,
    uint32_t n,
    PublicKey<DCRTPoly> publicKey,
    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> keyMap
) {
    auto ciphertext_n = cc->Encrypt(publicKey, cc->MakePackedPlaintext({ n }));
    
    std::vector<Ciphertext<DCRTPoly>> c(n);
    c[0] = cc->EvalMult(ciphertext, ciphertext_n);
        
    auto precomputed = cc->EvalFastRotationPrecompute(ciphertext);
    for(uint32_t i = 1; i < n; i++) {
        auto rotated = cc->EvalFastRotation(ciphertext, i, precomputed);
        c[i] = cc->EvalMult(rotated, ciphertext_n);
    }

    return c;
}


void TestA() {
    const uint32_t n = 4;           // bits
    const uint32_t log_n = Log2(n); // levels
    const uint32_t N = 16384;       // Smallest recommended value with BGN-rns (l = 3)?

    CCParams<CryptoContextBGVRNS> params;
    params.SetPlaintextModulus(65537);
    params.SetRingDim(N);
    params.SetMultiplicativeDepth(2*log_n - 1);
    // params.SetGadgetBase(2);
    // params.SetGadgetDigits(log_n);
    params.SetMaxRelinSkDeg(3);

    std::cout << "Created params (depth = " << 2*log_n - 1 << ")" << std::endl;

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::cout << "Created context" << std::endl;

    // Generate k-indices used in Algorithm 3 of https://eprint.iacr.org/2019/736
    auto indices = ExpandRLWEIndices(n);
    std::cout << "Generated indices: " << indices << std::endl;

    auto keyMap = cc->EvalAutomorphismKeyGen(keyPair.secretKey, indices);
    std::cout << "Created automorphism keys" << std::endl;

    // Encrypt a sample plaintext
    Plaintext plaintext = cc->MakePackedPlaintext({1, 1, 0, 1});
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    
    std::cout << "Encrypted plaintext " << plaintext << std::endl;

    auto subs = cc->EvalAutomorphism(ciphertext, 3, *keyMap); // DEBUG
    Plaintext debug_subs;
    cc->Decrypt(keyPair.secretKey, subs, &debug_subs);
    debug_subs->SetLength(n * 3);
    std::cout << "Automorphism subs: " << debug_subs << std::endl;

    // cc->EvalFastRotation()

    // auto rotations = { 1, -1, -3, -5, -17, 17, 9, 5, 3 };
    auto rotations = { 0, 1, 2, 3, 4 };
    cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
    // auto rotations = { -1, -2, -3, 16383, 16382, 16381, 1, 2, 3 };
    // cc->EvalRotateKeyGen(keyPair.secretKey, rotations);

    // for(auto r : rotations) {
    //     auto rotated = cc->EvalAtIndex(ciphertext, r);
    //     Plaintext debug_rotated;
    //     cc->Decrypt(keyPair.secretKey, rotated, &debug_rotated);
    //     debug_rotated->SetLength(40);
    //     std::cout << "Rotation " << r << ": " << debug_rotated << std::endl;
    // }

    // Try expanding the ciphertext into an RGSW ciphertext using the generated automorphism keys
    // auto rgswCiphertext = ExpandRLWE(cc, ciphertext, log_n, keyMap, keyPair); // log_n = 2 not 4 (n = number of bits?)
    auto rgswCiphertext = ExpandRLWENaive(cc, ciphertext, 4, keyPair.publicKey, keyMap);
    
    std::cout << "Expanded RLWE" << std::endl;

    // Decrypt the first ciphertext in the expanded RGSW ciphertext and check that it matches the original plaintext
    Plaintext decrypted;
    
    std::cout << "Original plaintext: " << plaintext << std::endl;
    std::cout << "Decrypted plaintext: " << std::endl; 
    
    for(const auto &c : rgswCiphertext) {
        cc->Decrypt(keyPair.secretKey, c, &decrypted);
        decrypted->SetLength(40);
        std::cout << decrypted << std::endl;
    }
}


void BFVrnsEvalRotate2n() {
    CCParams<CryptoContextBFVRNS> parameters;

    parameters.SetPlaintextModulus(65537);
    parameters.SetMaxRelinSkDeg(3);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    int32_t n = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;

    // Initialize the public key containers.
    KeyPair<DCRTPoly> kp = cc->KeyGen();

    std::vector<int32_t> indexList = {2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5};

    cc->EvalRotateKeyGen(kp.secretKey, indexList);

    std::vector<int64_t> vectorOfInts = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    vectorOfInts.resize(n);
    vectorOfInts[n - 1] = n;
    vectorOfInts[n - 2] = n - 1;
    vectorOfInts[n - 3] = n - 2;

    Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

    auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

    for (size_t i = 0; i < 18; i++) {
        auto permutedCiphertext = cc->EvalRotate(ciphertext, indexList[i]);

        Plaintext intArrayNew;

        cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

        intArrayNew->SetLength(10);

        std::cout << "Automorphed array - at index " << indexList[i] << ": " << *intArrayNew << std::endl;
    }
}