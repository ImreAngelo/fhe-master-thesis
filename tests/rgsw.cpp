#define TEST_INTERNAL_FUNCTIONS

#include "core/server/context.h"
#include "core/server/helpers.h"
#include "core/server/params.h"
#include "core/client/rgsw.h"

#include <cstdint>
#include <cmath>
#include <iostream>
#include <ranges>

/**
 * @brief Tests the internal functions of HomExpand
 */
inline void TestA(const std::vector<int64_t>& index) {
    using namespace lbcrypto;
    
    // Note: n is not number of users but log(number of users)
    const uint32_t n = index.size(); // bits
    const uint32_t log_n = Log2(n);  // levels

    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(2*log_n - 1);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);   // smallest recommended value with BGN-rns (l = 3)?
    params.SetMaxRelinSkDeg(3); // for rotations (TODO: confirm needed by EvalFastRotate)

    // RGSW-specific parameters
    params.SetGadgetLevels(log_n);
    params.SetGadgetBase(2);

    auto cc = Server::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    // encrypt a sample plaintext
    Plaintext plaintext = cc->MakePackedPlaintext(index);
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    
    #if defined(DEBUG_LOGGING)
    std::cout << "Encrypted plaintext " << plaintext << std::endl;
    #endif

    // rotations used are [1, n)
    std::vector<int> rotations(n - 1);
    std::iota(rotations.begin(), rotations.end(), 1);
    cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
    
    auto rgswCiphertext = cc->ExpandRLWEHoisted(ciphertext, keyPair.publicKey, n);

    // decrypt the first ciphertext in the expanded RGSW ciphertext and check that it matches the original plaintext
    Plaintext decrypted;
    
    #if defined(DEBUG_LOGGING)
    std::cout << "Original plaintext: " << plaintext << std::endl;
    std::cout << "Decrypted plaintext: " << std::endl; 
    PrintRGSW(cc, keyPair, rgswCiphertext, n);
    #endif

    // SUBTEST: Check correctness
    for(uint32_t i = 0; i < n; i++) {
        Plaintext p;
        cc->Decrypt(keyPair.secretKey, rgswCiphertext[i], &p);
        p->SetLength(n);

        SCOPED_TRACE("RGSW row " + std::to_string(i));
        ASSERT_EQ(index[i], p->GetPackedValue()[0]);
        
        // Check the remaining values are 0
        for(uint32_t j = 1; j < n; j++) {
            SCOPED_TRACE("Column " + std::to_string(j));
            ASSERT_EQ(0, p->GetPackedValue()[j]) << "RGSW row " << i << " did not have trailing 0's.";
        }
    }

    // // TODO: Simulate client and send RGSW(-s) serialized to ensure no secret key mismatch
    // CryptoContext<DCRTPoly> cc_ctx = cc;
    // auto A = Client::CreateRGSW_NegS(cc_ctx, keyPair, n, 2); // Input A

    // // // Second loop
    // // Initialize C as a list of matrices
    // for(uint32_t i = 0; i < n; i++) {
    //     // Initialize C[i] as an empty 2ell x 2 matrix of polynomials
    //     for(uint32_t k = 0; k < log_n; k++) {
    //         // C[i][k] = EvalExternalProduct(A, c[k][i])
    //         // C[i][k + log_n] = EvalExternalProduct(A, c[k][i])
    //     }
    // }

    // Finally, use external product to see that each C[i] is the correct RGSW(b[i]) encryption
}

// Small power-of-2 base
// TEST(RGSW, ExpandRLWEHoisted_4bit_01) { TestA({ 0, 0, 0, 1 }); }
// TEST(RGSW, ExpandRLWEHoisted_4bit_08) { TestA({ 1, 0, 0, 0 }); }
TEST(RGSW, ExpandRLWEHoisted_4bit_13) { TestA({ 1, 1, 0, 1 }); }

// Non-power-of-2 base
// TEST(RGSW, ExpandRLWEHoisted_12bit_0425) { TestA({ 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1 }); }
// TEST(RGSW, ExpandRLWEHoisted_12bit_2224) { TestA({ 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0 }); }
// TEST(RGSW, ExpandRLWEHoisted_12bit_3493) { TestA({ 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1 }); }


TEST(RGSW, EncryptRGSW) {
    using namespace lbcrypto;

    const auto index = std::vector<int64_t>{ 1, 0, 1, 0 };
    
    // Note: n is not number of users but log(number of users)
    const uint32_t n = index.size(); // bits
    const uint32_t log_n = Log2(n);  // levels

    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(2*log_n - 1);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);   // smallest recommended value with BGN-rns (l = 3)?
    params.SetMaxRelinSkDeg(3); // for rotations (TODO: confirm needed by EvalFastRotate)

    // RGSW-specific parameters
    // params.SetGadgetLevels(log_n);
    // params.SetGadgetBase(2);

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto rgsw_ct = Client::EncryptRGSW(cc, keyPair, index, 2);

    Plaintext pt = cc->MakePackedPlaintext(index);
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);

    Server::EvalExternalProduct(cc, keyPair.publicKey, rlwe_ct, rgsw_ct);
}

// /// @brief Test HomExpand
// void TestB() {
//     const auto index = std::vector<int64_t>{ 1, 1, 0, 1 };

//     const uint32_t n = index.size(); // bits
//     const uint32_t log_n = Log2(n);  // levels
//     const uint32_t N = 16384;        // Smallest recommended value with BGN-rns (l = 3)?

//     CCParams<CryptoContextBGVRNS> params;
//     params.SetMultiplicativeDepth(2*log_n - 1);
//     params.SetPlaintextModulus(65537);
//     params.SetRingDim(N);
//     params.SetMaxRelinSkDeg(3); // for rotations (TODO: confirm needed by EvalFastRotate)

//     CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
//     cc->Enable(PKE);
//     cc->Enable(KEYSWITCH);
//     cc->Enable(LEVELEDSHE);
//     cc->Enable(ADVANCEDSHE);

//     KeyPair<DCRTPoly> keyPair;
//     keyPair = cc->KeyGen();
//     cc->EvalMultKeyGen(keyPair.secretKey);

//     std::cout << "Created context" << std::endl;

//     // encrypt a sample plaintext
//     Plaintext plaintext = cc->MakePackedPlaintext(index);
//     auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    
//     std::cout << "Encrypted plaintext " << plaintext << std::endl;

//     // rotations used are [1, n)
//     auto rotations = { 0, 1, 2, 3 };
//     cc->EvalRotateKeyGen(keyPair.secretKey, rotations);

//     // TODO: rename n to.. ell?
//     auto inputs = core::server::ScaleToGadgetLevels(cc, ciphertext, n);

//     // decrypt the first ciphertext in the expanded RGSW ciphertext and check that it matches the original plaintext
//     std::cout << "Original plaintext: " << plaintext << std::endl;
//     std::cout << "\nGadget scaled: " << std::endl; 
//     PrintRGSW(cc, keyPair, inputs, n);

//     auto rgswCiphertexts = std::vector<std::vector<Ciphertext<DCRTPoly>>>(n);
//     for(size_t i = 0; i < n; i++) {
//         rgswCiphertexts[i] = core::server::HoistedExpandRLWE(cc, inputs[i], n, keyPair.publicKey);
//         std::cout << std::endl << "RGSW Ciphertext " << i << ":" << std::endl;
//         PrintRGSW(cc, keyPair, rgswCiphertexts[i], n);
//     }

//     // TODO: Create RGSW(-s)
//     auto rgsw_s = core::server::CreateRGSW_NegS(cc, keyPair, n, 2);

//     // Print secret key
//     auto sk_poly = keyPair.secretKey->GetPrivateElement();
//     sk_poly.SetFormat(Format::EVALUATION);
//     auto& sk_eval = sk_poly.GetElementAtIndex(0);

//     std::cout << "Secret key: " << sk_eval << std::endl;

//     // Print RGSW encryption of secret key
//     std::cout << "RGSW(-s): " << std::endl;
//     PrintRGSW(cc, keyPair, rgsw_s, n);

//     // Final loop: external product RGSW(-s) with the expanded RLWE ciphertexts

//     // TODO: decrypt to check that we get the original plaintext back
// }

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