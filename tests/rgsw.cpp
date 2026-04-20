#define TEST_INTERNAL_FUNCTIONS

#include "core/server/context.h"
#include "core/server/helpers.h"
#include "core/server/params.h"
#include "core/client/rgsw.h"
#include "server/HomPlacing.h"

#include <cstdint>
#include <cmath>
#include <iostream>
#include <ranges>

using namespace lbcrypto;

/**
 * @brief Test the external product
 * Should result in input value
 */
inline void TestExternalProduct(const std::vector<int64_t>& value) {
    // const auto index = std::vector<int64_t>{ 1, 0, 1, 0 };
    
    // Note: n is not number of users but log(number of users)
    // const uint32_t n = value.size(); // bits
    // const uint32_t log_n = Log2(n);  // levels
    
    // const uint64_t log_B = 30;
    // const size_t ell = 11;
    
    const uint64_t log_B = 15;
    const size_t ell = 21;

    CCParams<CryptoContextBGVRNS> params;
    // params.SetMultiplicativeDepth(2*ell - 1);
    // params.SetPlaintextModulus((1 << 17) + 1);
    // params.SetRingDim(1 << 16);     // 16384 = smallest recommended value with BGN-rns (l = 3)
    //                                 // 65535 for l = 17
    params.SetMultiplicativeDepth(7);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);   // smallest recommended value with BGN-rns (l = 3)?
    // params.SetMaxRelinSkDeg(3);

#if defined(DEBUG_LOGGING)
    std::cout << "Depth = " << params.GetMultiplicativeDepth() << std::endl;
    std::cout << "Ring Dim. = " << params.GetRingDim() << std::endl;
    std::cout << "Plaintext mod = " << params.GetPlaintextModulus() << std::endl;
#endif

    // RGSW-specific parameters
    // params.SetGadgetLevels(log_n);
    // params.SetGadgetBase(2);

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    // cc->Enable(ADVANCEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    
    auto rgsw_ct = Client::EncryptRGSW(cc, keyPair.secretKey, value, log_B, ell);
    
#if defined(DEBUG_LOGGING)
    std::cout << "G: " << std::endl;
    for(const auto& row : rgsw_ct) {
        Plaintext decrytedRow;
        cc->Decrypt(keyPair.secretKey, row, &decrytedRow);
        decrytedRow->SetLength(n);
        std::cout << decrytedRow << std::endl;
        // TODO: Assert bottom rows are correct
    }
#endif

    Plaintext pt = cc->MakePackedPlaintext(value);
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);

    Plaintext res_a;
    auto ntt = Server::EvalExternalProduct(cc, rlwe_ct, rgsw_ct, log_B, ell);
    cc->Decrypt(keyPair.secretKey, ntt, &res_a);
    std::cout << "Final result (NTT): " << res_a << std::endl;
    
    Plaintext res_b;
    auto cof = Server::EvalCoeffExternalProduct(cc, rlwe_ct, rgsw_ct, log_B, ell);
    cc->Decrypt(keyPair.secretKey, cof, &res_b);
    std::cout << "Final result (CoF): " << res_b << std::endl;
    
    Plaintext res_c;
    auto acc = Server::EvalAccExternalProduct(cc, rlwe_ct, rgsw_ct, log_B, ell);
    cc->Decrypt(keyPair.secretKey, acc, &res_c);
    std::cout << "Final result (Acc): " << res_c << std::endl;

    const auto& result_slot = res_a->GetPackedValue();
    for(size_t i = 0; i < value.size(); i++) {
        ASSERT_EQ(value[i], result_slot[i]);
    }
}

/**
 * @brief Test Homomorphic Placing (single user)
 * Should place value in slot 2^index
 */
inline void TestHomPlacing(const std::vector<int64_t>& index, const int64_t& value) {
    const uint64_t log_B = 15;
    const size_t ell = 21;

    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(7);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);

#if defined(DEBUG_LOGGING)
    std::cout << "Depth = " << params.GetMultiplicativeDepth() << std::endl;
    std::cout << "Ring Dim. = " << params.GetRingDim() << std::endl;
    std::cout << "Plaintext mod = " << params.GetPlaintextModulus() << std::endl;
#endif

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto rgsw_ct = Client::EncryptRGSW(cc, keyPair.secretKey, index, log_B, ell);

    std::vector<Client::RGSWCiphertext<DCRTPoly>> bits(1);
    bits[0] = rgsw_ct;

    Plaintext pt = cc->MakePackedPlaintext({ value });
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);

    auto res_cts = Server::HomPlacing(cc, rlwe_ct, bits, log_B, ell);
    
#if defined(DEBUG_LOGGING)
    std::cout << "Final placing: ";
    for(const auto& v : res_cts) {
        Plaintext res;
        cc->Decrypt(keyPair.secretKey, v, &res);
        std::cout << res << ", ";    
    }
#endif

    std::cout << std::endl;

    // Currently only correct for bit = 0
    const auto slot = std::accumulate(index.begin(), index.end(), 0, 
        [](int acc, bool bit) { return (acc << 1) | bit; });
    std::vector<int64_t> expected(1 << index.size());
    expected[slot] = value;

#if defined(DEBUG_LOGGING)
    std::cout << "Placing '" << value << "' in slot " << slot << std::endl;
#endif

    ASSERT_EQ(expected.size(), res_cts.size());

    for(size_t i = 0; i < expected.size(); i++) {
        Plaintext slot_val;
        cc->Decrypt(keyPair.secretKey, res_cts[i], &slot_val);
        ASSERT_EQ(expected[i], slot_val->GetPackedValue()[0]);
    }
}

/**
 * @brief Tests the internal functions of HomExpand
 */
inline void TestHomExpand(const std::vector<int64_t>& index) {
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

// Basic test
TEST(RGSW, EncryptRGSW) { TestExternalProduct({ 1, 0, 1, 0 }); } // fails

// Basic test
TEST(RGSW, HomPlacing_0) { TestHomPlacing({0}, 4); } // works 
TEST(RGSW, HomPlacing_1) { TestHomPlacing({1}, 4); } // fails because of external product

// Small power-of-2 base
// TEST(RGSW, ExpandRLWEHoisted_4bit_01) { TestHomExpand({ 0, 0, 0, 1 }); }
// TEST(RGSW, ExpandRLWEHoisted_4bit_08) { TestHomExpand({ 1, 0, 0, 0 }); }
// TEST(RGSW, ExpandRLWEHoisted_4bit_13) { TestHomExpand({ 1, 1, 0, 1 }); }

// Non-power-of-2 base
// TEST(RGSW, ExpandRLWEHoisted_12bit_0425) { TestHomExpand({ 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1 }); }
// TEST(RGSW, ExpandRLWEHoisted_12bit_2224) { TestHomExpand({ 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0 }); }
// TEST(RGSW, ExpandRLWEHoisted_12bit_3493) { TestHomExpand({ 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1 }); }


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