// #define TEST_INTERNAL_FUNCTIONS
#define CENTER(integer, modulus) (((integer) > (modulus) / 2) ? ((integer % (2*modulus)) - (modulus)) : (integer))

#include "core/context.h"
#include "core/helpers.h"
#include "core/params.h"
#include "core/rgsw.h"

#include "../cli_params.h"

#include <cstdint>
#include <cmath>
#include <iostream>


using namespace lbcrypto;

inline CCParams<CryptoContextRGSWBGV> GetParams(const uint32_t log_N = 11) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(test_cli::g_mult_depth.value_or(1));
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(2));
    params.SetRingDim(test_cli::g_ring_dim.value_or(1 << log_N));

    // TODO: What is the security parameter?
    params.SetSecurityLevel(SecurityLevel::HEStd_NotSet);

    params.SetMaxRelinSkDeg(0); // Force no relinearization keys

    DEBUG_PRINT("Depth = " << params.GetMultiplicativeDepth());
    DEBUG_PRINT("Ring Dim. = " << params.GetRingDim());
    DEBUG_PRINT("Plaintext mod = " << params.GetPlaintextModulus());

    return params;
}

/**
 * @brief Test RGSW encryption, the external product and internal product, using the textbook (un-optimized) implementations
 */
inline void RunTest(const std::vector<int64_t>& value, const int64_t log_b = 30) {
    const CCParams<CryptoContextRGSWBGV> params = GetParams();
    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    // cc->EvalMultKeyGen(keyPair.secretKey);
    
    // Set ell from B and Q
    const size_t log_q = cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB();
    const size_t ell = log_q / log_b + 1;
    DEBUG_PRINT("Log Q: " << log_q << " -> ell: " << ell);

    Plaintext pt = cc->MakePackedPlaintext(std::vector<int64_t>(value.size(), 1));
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);
    auto rgsw_ct = cc->Encrypt_Textbook(keyPair.publicKey, cc->MakePackedPlaintext(value), log_b, ell);
    
    // Test External Product
    {
        auto res_ct = cc->EvalExternalProduct_Textbook(rlwe_ct, rgsw_ct, log_b);

        Plaintext res;
        cc->Decrypt(keyPair.secretKey, res_ct, &res);
        res->SetLength(std::max(static_cast<size_t>(8), value.size()));
    
        const auto& result_slot = res->GetPackedValue();
        for (size_t i = 0; i < value.size(); i++) {
            auto modval = CENTER(value[i], static_cast<int64_t>(params.GetPlaintextModulus()));
            ASSERT_EQ(modval, result_slot[i]);
        }
    }

    // Test Internal Product
    {
        auto rgsw_sq = cc->EvalInternalProduct_Textbook(rgsw_ct, rgsw_ct, log_b);
        auto sq_ct   = cc->EvalExternalProduct_Textbook(rlwe_ct, rgsw_sq, log_b);

        Plaintext res;
        cc->Decrypt(keyPair.secretKey, sq_ct, &res);

        const auto& result_slot = res->GetPackedValue();
        for (size_t i = 0; i < value.size(); i++) {
            auto valsqr = value[i] * value[i];
            auto modvalsqr = CENTER(valsqr, static_cast<int64_t>(params.GetPlaintextModulus()));
            ASSERT_EQ(modvalsqr, result_slot[i]);
        }
    }
    
    // TODO: Test noise/mult depth growth
    { 
        // ...
    }
}

// Test basic functionality
TEST(RGSW_Textbook, b0)    { RunTest({ 0 }); }
TEST(RGSW_Textbook, b1)    { RunTest({ 1 }); }
TEST(RGSW_Textbook, d2)    { RunTest({ 2 }); }
TEST(RGSW_Textbook, inv)   { RunTest({ 256 }); }
TEST(RGSW_Textbook, max)   { RunTest({ 65536 }); }
TEST(RGSW_Textbook, b00)   { RunTest({ 0, 0 }); }
TEST(RGSW_Textbook, b01)   { RunTest({ 0, 1 }); }
TEST(RGSW_Textbook, b10)   { RunTest({ 1, 0 }); }
TEST(RGSW_Textbook, b11)   { RunTest({ 1, 1 }); }

// Test all slots are usable
TEST(RGSW_Textbook, x8)   { RunTest(std::vector<int64_t>(8, 65536)); }
TEST(RGSW_Textbook, x64)  { RunTest(std::vector<int64_t>(64, 65536)); }
TEST(RGSW_Textbook, x16k) { RunTest(std::vector<int64_t>(16384, 65536)); }

// Expect failure; plaintext too large
TEST(RGSW_Textbook, over) { 
    EXPECT_THROW(RunTest({ 65537 }), lbcrypto::OpenFHEException); 
    EXPECT_THROW(RunTest(std::vector<int64_t>(16385, 65536)), lbcrypto::OpenFHEException); 
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
