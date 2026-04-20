#define TEST_INTERNAL_FUNCTIONS

#include "core/server/context.h"
#include "core/server/helpers.h"
#include "core/server/params.h"
#include "core/client/rgsw.h"

#include <cstdint>
#include <cmath>
#include <iostream>
#include <ranges>

using namespace lbcrypto;

template <typename CC, typename T>
inline void PrintRGSW(const CC& cc, const lbcrypto::KeyPair<T> keys, const std::vector<lbcrypto::Ciphertext<T>>& vec, size_t);

/**
 * @brief Test the external product
 * Should result in input value
 */
inline void TestExternalProduct(const std::vector<int64_t>& value) {
    // Note: n is not number of users but log(number of users)
    // const uint32_t n = value.size(); // bits
    // const uint32_t log_n = Log2(n);  // levels
    
    // TODO: Use params.SetGadgetBase(...) etc.
    const uint64_t log_B = 15;
    const size_t ell = 6; // TODO: Auto select

    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(1);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);

    // Avoid per-level scaling factor 
    // RGSW rows are built by hand, so we need S_L = 1
    params.SetScalingTechnique(FIXEDAUTO);  

#if defined(DEBUG_LOGGING)
    std::cout << "Depth = " << params.GetMultiplicativeDepth() << std::endl;
    std::cout << "Ring Dim. = " << params.GetRingDim() << std::endl;
    std::cout << "Plaintext mod = " << params.GetPlaintextModulus() << std::endl;
#endif

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    
    auto rgsw_ct = Client::EncryptRGSW(cc, keyPair.secretKey, value, log_B, ell);
    
#if defined(DEBUG_LOGGING)
    std::cout << "G: " << std::endl;
    PrintRGSW(cc, keyPair, rgsw_ct, value.size());
#endif

    Plaintext pt = cc->MakePackedPlaintext(value);
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);

    Plaintext res;
    auto res_ct = Server::EvalExternalProduct(cc, rlwe_ct, rgsw_ct, log_B, ell);
    cc->Decrypt(keyPair.secretKey, res_ct, &res);
    
#if defined(DEBUG_LOGGING)
    std::cout << "Final result: " << res_a << std::endl;
#endif

    const auto& result_slot = res->GetPackedValue();
    for(size_t i = 0; i < value.size(); i++) {
        ASSERT_EQ(value[i], result_slot[i]);
    }
}

// Basic test
TEST(ExtProduct, b0)    { TestExternalProduct({ 0 }); }
TEST(ExtProduct, b1)    { TestExternalProduct({ 1 }); }
TEST(ExtProduct, b1010) { TestExternalProduct({ 1, 0, 1, 0 }); }


/// @brief Print a list of ciphertexts 
template <typename CC, typename T>
inline void PrintRGSW(
    const CC& cc, 
    const lbcrypto::KeyPair<T> keys, 
    const std::vector<lbcrypto::Ciphertext<T>>& vec, 
    size_t columns
) {
    lbcrypto::Plaintext plaintext;
    for(const auto &c : vec) {
        cc->Decrypt(keys.secretKey, c, &plaintext);
        plaintext->SetLength(columns);
        std::cout << plaintext << std::endl;
    }
}

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