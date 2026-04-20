#include "core/server/context.h"
#include "core/server/helpers.h"
#include "core/server/params.h"

using namespace lbcrypto;

/**
 * @brief Tests the internal functions of HomExpand
 */
inline void TestHomExpand(const std::vector<int64_t>& index) {
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
    
    // auto rgswCiphertext = cc->ExpandRLWEHoisted(ciphertext, keyPair.publicKey, n);

    // // decrypt the first ciphertext in the expanded RGSW ciphertext and check that it matches the original plaintext
    // Plaintext decrypted;
    
    // #if defined(DEBUG_LOGGING)
    // std::cout << "Original plaintext: " << plaintext << std::endl;
    // std::cout << "Decrypted plaintext: " << std::endl; 
    // PrintRGSW(cc, keyPair, rgswCiphertext, n);
    // #endif

    // // SUBTEST: Check correctness
    // for(uint32_t i = 0; i < n; i++) {
    //     Plaintext p;
    //     cc->Decrypt(keyPair.secretKey, rgswCiphertext[i], &p);
    //     p->SetLength(n);

    //     SCOPED_TRACE("RGSW row " + std::to_string(i));
    //     ASSERT_EQ(index[i], p->GetPackedValue()[0]);
        
    //     // Check the remaining values are 0
    //     for(uint32_t j = 1; j < n; j++) {
    //         SCOPED_TRACE("Column " + std::to_string(j));
    //         ASSERT_EQ(0, p->GetPackedValue()[j]) << "RGSW row " << i << " did not have trailing 0's.";
    //     }
    // }

    // // // TODO: Simulate client and send RGSW(-s) serialized to ensure no secret key mismatch
    // // CryptoContext<DCRTPoly> cc_ctx = cc;
    // // auto A = Client::CreateRGSW_NegS(cc_ctx, keyPair, n, 2); // Input A

    // // // // Second loop
    // // // Initialize C as a list of matrices
    // // for(uint32_t i = 0; i < n; i++) {
    // //     // Initialize C[i] as an empty 2ell x 2 matrix of polynomials
    // //     for(uint32_t k = 0; k < log_n; k++) {
    // //         // C[i][k] = EvalExternalProduct(A, c[k][i])
    // //         // C[i][k + log_n] = EvalExternalProduct(A, c[k][i])
    // //     }
    // // }

    // // Finally, use external product to see that each C[i] is the correct RGSW(b[i]) encryption
}

// Small power-of-2 base
// TEST(HomExpand, ExpandRLWEHoisted_4bit_01) { TestHomExpand({ 0, 0, 0, 1 }); }
// TEST(HomExpand, ExpandRLWEHoisted_4bit_08) { TestHomExpand({ 1, 0, 0, 0 }); }
// TEST(HomExpand, ExpandRLWEHoisted_4bit_13) { TestHomExpand({ 1, 1, 0, 1 }); }

// Non-power-of-2 base
// TEST(HomExpand, ExpandRLWEHoisted_12bit_0425) { TestHomExpand({ 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1 }); }
// TEST(HomExpand, ExpandRLWEHoisted_12bit_2224) { TestHomExpand({ 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0 }); }
// TEST(HomExpand, ExpandRLWEHoisted_12bit_3493) { TestHomExpand({ 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1 }); }