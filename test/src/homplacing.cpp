#include "server/homplacing.h"

using namespace lbcrypto;


/**
 * @brief Test Homomorphic Placing (single user)
 *        Should place value in slot 2^index (binary)
 */
inline void TestHomPlacing(const std::vector<int64_t>& index, const int64_t& value) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(2);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);
    
    // Avoid per-level scaling factor 
    // RGSW rows are built by hand, so we need S_L = 1
    // TODO: Set automatically in RGSW encrypt?
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetGadgetBase(30);
    params.SetGadgetDecomposition(5);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<RGSWCiphertext<DCRTPoly>> bits;
    bits.reserve(index.size());

    for(const auto& bit : index) {
        bits.emplace_back(cc->EncryptRGSW(keyPair.publicKey, { bit }));
    }

    Plaintext pt = cc->MakePackedPlaintext({ value });
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);

    auto res_cts = Server::HomPlacing(cc, rlwe_ct, bits);
    
#if defined(DEBUG_LOGGING)
    std::cout << "Final placing: ";
    for(const auto& v : res_cts) {
        Plaintext res;
        cc->Decrypt(keyPair.secretKey, v, &res);
        std::cout << res << ", ";    
    }
    std::cout << std::endl;
#endif

    const auto slot = std::accumulate(index.begin(), index.end(), 0, 
        [](int acc, bool bit) { return (acc << 1) | bit; });
    std::vector<int64_t> expected(1 << index.size());
    expected[slot] = value;

#if defined(DEBUG_LOGGING)
    std::cout << "Placing '" << value << "' in slot " << slot << std::endl;
    std::cout << expected << std::endl;
#endif

    ASSERT_EQ(expected.size(), res_cts.size());

    for(size_t i = 0; i < expected.size(); i++) {
        Plaintext slot_val;
        cc->Decrypt(keyPair.secretKey, res_cts[i], &slot_val);
        ASSERT_EQ(expected[i], slot_val->GetPackedValue()[0]);
    }
}

// TODO: Test HomPlacing without RGSW for comparison

TEST(HomPlacing, b0)    { TestHomPlacing({0}, 4); }
TEST(HomPlacing, b1)    { TestHomPlacing({1}, 4); }
TEST(HomPlacing, x2_0)  { TestHomPlacing({0, 0}, 4); }
TEST(HomPlacing, x2_1)  { TestHomPlacing({1, 0}, 4); }
TEST(HomPlacing, x2_2)  { TestHomPlacing({0, 1}, 4); }
TEST(HomPlacing, x2_3)  { TestHomPlacing({1, 1}, 4); }
TEST(HomPlacing, x3)    { TestHomPlacing({0, 1, 1}, 4); }
TEST(HomPlacing, x4)    { TestHomPlacing({1, 1, 0, 1}, 4); }
TEST(HomPlacing, x5)    { TestHomPlacing({1, 0, 1, 1, 0}, 4); }
// TEST(HomPlacing, x6) { TestHomPlacing({1, 0, 1, 1, 0, 1}, 4); }      // TODO: Auto-set parameters
// TEST(HomPlacing, x7) { TestHomPlacing({1, 0, 1, 0, 1, 0, 1}, 4); }   //  ----------''-----------