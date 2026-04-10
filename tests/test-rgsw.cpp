#include "core/include/rgsw.h"
#include "openfhe.h"

// modinv
#include "math/nbtheory.h"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <iostream>

using namespace lbcrypto;

void TestA();
void TestB();

int main() {
    // TestA();
    TestB();
    return 0;
}

/**
 * @brief returns 2^n
 * @param n the exponent
 * @return 2^n
 */
template <typename T>
constexpr inline T Log2(T n) {
    T k = 0;
    while ((T(1) << k) < n) {
        k++;
    }
    return k;
}

/// @brief Test ExpandRLWE
void TestA() {
    const auto index = std::vector<int64_t>{ 1, 1, 0, 1 };

    const uint32_t n = index.size(); // bits
    const uint32_t log_n = Log2(n);  // levels
    const uint32_t N = 16384;        // Smallest recommended value with BGN-rns (l = 3)?

    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(2*log_n - 1);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(N);
    params.SetMaxRelinSkDeg(3); // for rotations (TODO: confirm needed by EvalFastRotate)

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::cout << "Created context" << std::endl;

    // encrypt a sample plaintext
    Plaintext plaintext = cc->MakePackedPlaintext({1, 1, 0, 1});
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    
    std::cout << "Encrypted plaintext " << plaintext << std::endl;

    // rotations used are [1, n)
    auto rotations = { 0, 1, 2, 3 };
    cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
    
    auto rgswCiphertext = core::server::HoistedExpandRLWE(cc, ciphertext, 4, keyPair.publicKey);
    
    std::cout << "Expanded RLWE" << std::endl;

    // decrypt the first ciphertext in the expanded RGSW ciphertext and check that it matches the original plaintext
    Plaintext decrypted;
    
    std::cout << "Original plaintext: " << plaintext << std::endl;
    std::cout << "Decrypted plaintext: " << std::endl; 
    
    for(const auto &c : rgswCiphertext) {
        cc->Decrypt(keyPair.secretKey, c, &decrypted);
        decrypted->SetLength(40);
        std::cout << decrypted << std::endl;
    }
}

/**
 * @todo Choose integer size from (cmake) parameter
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
    uint64_t t = (cc->GetCryptoParameters()->GetPlaintextModulus());

    std::cout << "Scaling ciphertext to gadget levels with B = " << B << " and t = " << t << std::endl;

#if defined(ASSERTIONS) && ASSERTIONS == 1
    assert(GreatestCommonDivisor(B, t) == 1 && "B and t must be coprime for the modular inverse to exist");
#endif

    for (uint32_t k = 0; k < ell; k++) {
        NativeInteger t_nat(t);
        NativeInteger Bk(1);
        NativeInteger B_nat(B);
        for (uint32_t j = 0; j <= k; j++)
            Bk = Bk.ModMul(B_nat, t_nat);

        int64_t Bk_inv = static_cast<int64_t>(
            Bk.ModInverse(t_nat).ConvertToInt<uint64_t>()
        );

        // Reduce to centered representation [-t/2, t/2]
        if (Bk_inv > static_cast<int64_t>(t / 2))
            Bk_inv -= static_cast<int64_t>(t);

        std::cout << "Level " << k << ": B^k = " << Bk << ", B^{-k} = " << Bk_inv << std::endl;

        // Scalar polynomial: just the constant term B^{-(k+1)}
        std::vector<int64_t> scalar(ell, Bk_inv);

        std::cout << "Scalar polynomial: " << scalar[0] << std::endl;
        
        auto pt   = cc->MakePackedPlaintext(scalar);
        result[k] = cc->EvalMult(ct, pt);
    }
    return result;
}

/// @brief Test HomExpand
void TestB() {
    const auto index = std::vector<int64_t>{ 1, 1, 0, 1 };

    const uint32_t n = index.size(); // bits
    const uint32_t log_n = Log2(n);  // levels
    const uint32_t N = 16384;        // Smallest recommended value with BGN-rns (l = 3)?

    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(2*log_n - 1);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(N);
    params.SetMaxRelinSkDeg(3); // for rotations (TODO: confirm needed by EvalFastRotate)

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::cout << "Created context" << std::endl;

    // encrypt a sample plaintext
    Plaintext plaintext = cc->MakePackedPlaintext(index);
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    
    std::cout << "Encrypted plaintext " << plaintext << std::endl;

    // // rotations used are [1, n)
    // auto rotations = { 0, 1, 2, 3 };
    // cc->EvalRotateKeyGen(keyPair.secretKey, rotations);

    // TODO: rename n to.. ell?
    auto inputs = ScaleToGadgetLevels(cc, ciphertext, n);

    // decrypt the first ciphertext in the expanded RGSW ciphertext and check that it matches the original plaintext
    std::cout << "Original plaintext: " << plaintext << std::endl;
    std::cout << "Decrypted: " << std::endl; 
    
    for(const auto &c : inputs) {
        cc->Decrypt(keyPair.secretKey, c, &plaintext);
        plaintext->SetLength(n);
        std::cout << plaintext << std::endl;
    }
}

/**
 * @brief returns 2^n
 * @param n the exponent
 * @return 2^n
 */
/*
template <typename T>
constexpr inline T Pow2(T k) {
    return (T(1) << k);
}
*/

/*
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
*/

/**
 * @brief Generates the indices used in Algorithm 3 of https://eprint.iacr.org/2019/736
 * 
 * @param log_n The number of digits in the binary representation of ...
 */
/*
template <typename T>
constexpr inline std::vector<T> ExpandRLWEIndices(T log_n) {
    std::vector<T> sizes;
    for (uint32_t i = 0; i < log_n; i++)
        sizes.push_back(Pow2(log_n - i) + 1);
    return sizes;
}
*/

/**
 * @brief Algorithm 3 of https://eprint.iacr.org/2019/736
 * 
 * @param cc the crypto context
 * @param ct the ciphertext to expand
 * @param log_n the number of digits in the binary representation of n, where n is
 * the number of ciphertexts in the output RGSW ciphertext
 * @param keyMap the evaluation keys for the automorphisms index k
 * @returns a vector of ciphertexts c[i] that encrypt n * ct[i]
 */
/*
template <typename T, typename N = uint32_t>
inline std::vector<Ciphertext<T>> ExpandRLWE(
    CryptoContext<T>& cc, 
    Ciphertext<T>& ct,
    N log_n,
    std::shared_ptr<std::map<N, lbcrypto::EvalKey<T>>> keyMap
) {
    auto n = N(1) << log_n;

    // The BGV/TFHE controversy
    assert(n == cc->GetCryptoParameters()->GetRingDimension() && "n must be equal to the ring dimension for the ORAM expandRlwe to work");

    std::vector<Ciphertext<T>> c(n);
    c[0] = ct;
    
    // monomial X^{-2^i}
    std::vector<int64_t> mono(n, 0);
    
    for(N i = 0; i < 4; i++) {
        N k = Pow2(log_n - i) + 1;
        N stride = Pow2(i);

        // Build X^{-stride} = -X^{ring_dim - stride}
        mono[n - stride] = -1;
        auto X_inv_stride = cc->MakeCoefPackedPlaintext(mono);
        
        // NOTE: Original paper uses b in [0, 2^i - 1], which is probably meant to be [0, 2^{i - 1} - 1] to not exceed n
        //       We also 0-index i, so we do not need to subtract 1
        for(auto b = int(Pow2(i)) - 1; b >= 0; b--) {
            auto cb = c[b];
            auto subs = cc->EvalAutomorphism(cb, k, *keyMap);
            auto diff = cc->EvalSub(cb, subs);
            
            // Update rows
            c[2*b] = cc->EvalAdd(cb, subs);
            c[2*b + 1] = cc->EvalMult(diff, X_inv_stride);
        }
        
        mono[n - stride] = 0;
    }
    
    return c;
}
*/

/*
void TestB() {
    const auto index = std::vector<int64_t>{ 1, 1, 0, 1 };

    const uint32_t n = index.size(); // bits
    const uint32_t log_n = Log2(n);  // levels
    const uint32_t N = 65536;        // Smallest recommended value with BGN-rns (l = 3)?

    CCParams<CryptoContextBGVRNS> params;
    params.SetPlaintextModulus(65537);
    params.SetRingDim(N);
    params.SetMultiplicativeDepth(2*Log2(N) - 1);
    params.SetMaxRelinSkDeg(3);

    std::cout << "Created params (depth = " << 2*log_n - 1 << ")" << std::endl;

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
    auto indices = ExpandRLWEIndices(n);
    std::cout << "Generated indices: " << indices << std::endl;

    auto keyMap = cc->EvalAutomorphismKeyGen(keyPair.secretKey, indices);
    std::cout << "Created automorphism keys" << std::endl;

    Plaintext plaintext = cc->MakeCoefPackedPlaintext(index);
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    
    std::cout << "Encrypted plaintext " << plaintext << std::endl;

    auto rgswCiphertext = ExpandRLWE(cc, ciphertext, n, keyMap); // n = number of bits
 
    std::cout << "Expanded RLWE" << std::endl;

    Plaintext decrypted;
    
    std::cout << "Original plaintext: " << plaintext << std::endl;
    std::cout << "Decrypted plaintext: " << std::endl; 
    
    for(const auto &c : rgswCiphertext) {
        cc->Decrypt(keyPair.secretKey, c, &decrypted);
        decrypted->SetLength(n);
        std::cout << decrypted << std::endl;
    }
}
*/