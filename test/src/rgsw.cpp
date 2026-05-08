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
    params.SetMultiplicativeDepth(test_cli::g_mult_depth.value_or(2));
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(1 << 2));
    params.SetRingDim(test_cli::g_ring_dim.value_or(1 << log_N));
    // params.SetScalingTechnique(FIXEDMANUAL); // TODO: Check if this is better for noise growth

    // TODO: What is the security parameter now?
    params.SetSecurityLevel(SecurityLevel::HEStd_NotSet);

    params.SetMaxRelinSkDeg(0); // Force no relinearization keys

    DEBUG_PRINT("Depth = " << params.GetMultiplicativeDepth());
    DEBUG_PRINT("Ring Dim. = " << params.GetRingDim());
    DEBUG_PRINT("Plaintext mod = " << params.GetPlaintextModulus());

    return params;
}

/**
 * @brief Test RGSW encryption, the external product and internal product, using the naive implementations
 */
inline void RunTest(const std::vector<int64_t>& value, const int64_t log_b = 15) {
    const CCParams<CryptoContextRGSWBGV> params = GetParams();
    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    
    // Set ell from B and Q
    const size_t log_q = cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB();
    const size_t ell = log_q / log_b + 1;
    DEBUG_PRINT("Log Q: " << log_q << " -> ell: " << ell);

    auto rlwe_ct = cc->Encrypt(keyPair.publicKey,  cc->MakeCoefPackedPlaintext({1}));
    auto rgsw_ct = cc->EncryptRGSW(keyPair.publicKey, cc->MakeCoefPackedPlaintext(value), log_b, ell);
    
    // Test External Product
    // Should return the original value
    {
        auto res_ct = cc->EvalExternalProduct(rlwe_ct, rgsw_ct, log_b);

        Plaintext res;
        cc->Decrypt(keyPair.secretKey, res_ct, &res);
        
        const auto& result_slot = res->GetCoefPackedValue();

        for (size_t i = 0; i < value.size(); i++) {
            auto modval = CENTER(value[i], static_cast<int64_t>(params.GetPlaintextModulus()));
            ASSERT_EQ(modval, result_slot[i]) << "slot " << i << std::endl;
        }
    }

    // Test Internal Product
    // Should return value^2 (polynomial multiplication)
    // TODO: Either do RGSW(1) x RGSW(value) or do RLWE(value) x RGSW(value) in external product test
    {
        auto rgsw_sq = cc->EvalInternalProduct(rgsw_ct, rgsw_ct, log_b);
        auto sq_ct   = cc->EvalExternalProduct(rlwe_ct, rgsw_sq, log_b);

        Plaintext res;
        cc->Decrypt(keyPair.secretKey, sq_ct, &res);
        
        const auto& result_slot = res->GetCoefPackedValue();
        
        const size_t N = cc->GetRingDimension();
        const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());
        std::vector<int64_t> expected(N, 0);

        // TODO: Abstract into a helper for polynomial multiplication mod (x^N+1, t)
        for (size_t i = 0; i < value.size(); i++)
            for (size_t j = 0; j < value.size(); j++) {
                size_t k = i + j;
                if (k < N) expected[k] += value[i] * value[j];
                else expected[k - N] -= value[i] * value[j];  // x^N = -1 in Z[x]/(x^N+1)
            }
        for (size_t k = 0; k < N; k++) {
            expected[k] = ((expected[k] % t) + t) % t;  // TODO: use CENTER macro
            if (expected[k] > t / 2) expected[k] -= t;
        }

        for (size_t k = 0; k < N; k++)
            ASSERT_EQ(expected[k], result_slot[k]) << "coeff " << k << std::endl;
    }
    
    // TODO: Test noise/mult depth growth
    { 
        // ...
    }
}

// Test basic functionality
TEST(RGSW, b0)    { RunTest({ 0 }); }
TEST(RGSW, b1)    { RunTest({ 1 }); }
TEST(RGSW, d2)    { RunTest({ 2 }); }
TEST(RGSW, b00)   { RunTest({ 0, 0 }); }
TEST(RGSW, b01)   { RunTest({ 0, 1 }); }
TEST(RGSW, b10)   { RunTest({ 1, 0 }); }
TEST(RGSW, b11)   { RunTest({ 1, 1 }); }
// TEST(RGSW, inv)   { RunTest({ 256 }); }
// TEST(RGSW, max)   { RunTest({ 65536 }); }

// Test all slots are usable
TEST(RGSW, x8)  { RunTest(std::vector<int64_t>(8, 1)); }
TEST(RGSW, x64) { RunTest(std::vector<int64_t>(64, 1)); }
TEST(RGSW, x2k) { RunTest(std::vector<int64_t>(2048, 1)); }

// Expect failure; plaintext too large
TEST(RGSW, over) { 
    EXPECT_THROW(RunTest({ 65537 }), lbcrypto::OpenFHEException); 
    EXPECT_THROW(RunTest(std::vector<int64_t>(16385, 65536)), lbcrypto::OpenFHEException); 
}

// Run all tests by default
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
