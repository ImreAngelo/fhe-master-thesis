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

inline CCParams<CryptoContextRGSWBGV> GetParams() {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(test_cli::g_mult_depth.value_or(3));
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
    params.SetRingDim(test_cli::g_ring_dim.value_or(1 << 14));
    params.SetNumLargeDigits(2);

    // RGSW rows are built by hand → avoid per-level scaling (S_L = 1 needed).
    params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDMANUAL));

    DEBUG_PRINT("Depth = " << params.GetMultiplicativeDepth());
    DEBUG_PRINT("Ring Dim. = " << params.GetRingDim());
    DEBUG_PRINT("Plaintext mod = " << params.GetPlaintextModulus());

    return params;
}

/**
 * @brief Test RGSW encryption, the external product and internal product
 */
inline void RunTest(const std::vector<int64_t>& value) {
    const CCParams<CryptoContextRGSWBGV> params = GetParams();
    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    
    Plaintext pt = cc->MakePackedPlaintext(std::vector<int64_t>(value.size(), 1));
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);
    auto rgsw_ct = cc->EncryptRGSW(keyPair.secretKey, cc->MakePackedPlaintext(value));

    DEBUG_PRINT("RGSW dnum = " << rgsw_ct.size());
    
    // Test External Product
    {
        auto res_ct = cc->EvalExternalProduct(rlwe_ct, rgsw_ct);

        Plaintext res;
        cc->Decrypt(keyPair.secretKey, res_ct, &res);
        res->SetLength(value.size());
    
        DEBUG_PRINT("Final result: " << res);
    
        const auto& result_slot = res->GetPackedValue();
        for (size_t i = 0; i < value.size(); i++) {
            auto modval = CENTER(value[i], static_cast<int64_t>(params.GetPlaintextModulus()));
            ASSERT_EQ(modval, result_slot[i]);
        }
    }

    // Test Internal Product
    {
        auto rgsw_sq = cc->EvalInternalProduct(rgsw_ct, rgsw_ct);
        auto sq_ct   = cc->EvalExternalProduct(rlwe_ct, rgsw_sq);

        Plaintext res;
        cc->Decrypt(keyPair.secretKey, sq_ct, &res);
        res->SetLength(value.size());

        DEBUG_PRINT("Internal product result: " << res);

        const auto& result_slot = res->GetPackedValue();
        for (size_t i = 0; i < value.size(); i++) {
            auto valsqr = value[i] * value[i];
            auto modvalsqr = CENTER(valsqr, static_cast<int64_t>(params.GetPlaintextModulus()));
            ASSERT_EQ(modvalsqr, result_slot[i]);
        }
    }

    // Test Plaintext x RGSW (EvalMultPlain)
    // TODO: Refactor -> Overload EvalMult
    {
        constexpr int64_t scale = 3;
        auto pt_scale  = cc->MakePackedPlaintext(std::vector<int64_t>(value.size(), scale));
        auto rgsw_mul  = cc->EvalMultPlain(pt_scale, rgsw_ct);
        auto out_ct    = cc->EvalExternalProduct(rlwe_ct, rgsw_mul);

        Plaintext res;
        cc->Decrypt(keyPair.secretKey, out_ct, &res);
        res->SetLength(value.size());

        DEBUG_PRINT("EvalMultPlain result: " << res);

        const auto& result_slot = res->GetPackedValue();
        for (size_t i = 0; i < value.size(); i++) {
            auto modval = CENTER(value[i] * scale, static_cast<int64_t>(params.GetPlaintextModulus()));
            ASSERT_EQ(modval, result_slot[i]);
        }
    }

    // Test noise/mult depth growth
    { 
        

    }
}

// Test basic functionality
TEST(RGSW, b0)    { RunTest({ 0 }); }
TEST(RGSW, b1)    { RunTest({ 1 }); }
TEST(RGSW, d2)    { RunTest({ 2 }); }
TEST(RGSW, inv)   { RunTest({ 256 }); }
TEST(RGSW, max)   { RunTest({ 65536 }); }
TEST(RGSW, b00)   { RunTest({ 0, 0 }); }
TEST(RGSW, b01)   { RunTest({ 0, 1 }); }
TEST(RGSW, b10)   { RunTest({ 1, 0 }); }
TEST(RGSW, b11)   { RunTest({ 1, 1 }); }

// // Test slots
// TEST(RGSW, x4)    { RunTest(std::vector<int64_t>(4, 65536)); }
// TEST(RGSW, x8)    { RunTest(std::vector<int64_t>(8, 65536)); }
// TEST(RGSW, x16)   { RunTest(std::vector<int64_t>(16, 65536)); }
// TEST(RGSW, x32)   { RunTest(std::vector<int64_t>(32, 65536)); }
// TEST(RGSW, x64)   { RunTest(std::vector<int64_t>(64, 65536)); }
// TEST(RGSW, x128)  { RunTest(std::vector<int64_t>(128, 65536)); }
// TEST(RGSW, x256)  { RunTest(std::vector<int64_t>(256, 65536)); }
// TEST(RGSW, x512)  { RunTest(std::vector<int64_t>(512, 65536)); }

/**
 * @brief Test RGSW encryption, the external product and internal product, using the textbook (un-optimized) implementations
 */
inline void RunTest_Textbook(const std::vector<int64_t>& value) {
    const CCParams<CryptoContextRGSWBGV> params = GetParams();
    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    constexpr int64_t log_b = 30;

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    
    Plaintext pt = cc->MakePackedPlaintext(std::vector<int64_t>(value.size(), 1));
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);
    auto rgsw_ct = cc->Encrypt_Textbook(keyPair.publicKey, cc->MakePackedPlaintext(value), log_b, 6);

    DEBUG_PRINT("RGSW dnum = " << rgsw_ct.size());
    
    // Test External Product
    {
        auto res_ct = cc->EvalExternalProduct_Textbook(rlwe_ct, rgsw_ct, log_b);

        Plaintext res;
        cc->Decrypt(keyPair.secretKey, res_ct, &res);
        res->SetLength(value.size());
    
        DEBUG_PRINT("Final result: " << res);
    
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
        res->SetLength(value.size());

        DEBUG_PRINT("Internal product result: " << res);

        const auto& result_slot = res->GetPackedValue();
        for (size_t i = 0; i < value.size(); i++) {
            auto valsqr = value[i] * value[i];
            auto modvalsqr = CENTER(valsqr, static_cast<int64_t>(params.GetPlaintextModulus()));
            ASSERT_EQ(modvalsqr, result_slot[i]);
        }
    }
}

TEST(RGSW_Textbook, b0)    { RunTest_Textbook({ 0 }); }
TEST(RGSW_Textbook, b1)    { RunTest_Textbook({ 1 }); }
TEST(RGSW_Textbook, d2)    { RunTest_Textbook({ 2 }); }
TEST(RGSW_Textbook, inv)   { RunTest_Textbook({ 256 }); }
TEST(RGSW_Textbook, max)   { RunTest_Textbook({ 65536 }); }
TEST(RGSW_Textbook, b00)   { RunTest_Textbook({ 0, 0 }); }
TEST(RGSW_Textbook, b01)   { RunTest_Textbook({ 0, 1 }); }
TEST(RGSW_Textbook, b10)   { RunTest_Textbook({ 1, 0 }); }
TEST(RGSW_Textbook, b11)   { RunTest_Textbook({ 1, 1 }); }

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
