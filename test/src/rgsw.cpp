#define TEST_INTERNAL_FUNCTIONS
#define DEBUG_LOGGING

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
    params.SetMultiplicativeDepth(2);
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
    params.SetRingDim(test_cli::g_ring_dim.value_or(16384));

    // RGSW rows are built by hand → avoid per-level scaling (S_L = 1 needed).
    // params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDAUTO));
    params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDMANUAL));

    DEBUG_PRINT("Depth = " << params.GetMultiplicativeDepth());
    DEBUG_PRINT("Ring Dim. = " << params.GetRingDim());
    DEBUG_PRINT("Plaintext mod = " << params.GetPlaintextModulus());

    return params;
}

inline void RunTest(const std::vector<int64_t>& value) {
    const CCParams<CryptoContextRGSWBGV> params = GetParams();
    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto rgsw_ct = cc->EncryptRGSW(keyPair.secretKey, value);

    DEBUG_PRINT("RGSW dnum = " << rgsw_ct.size());

    Plaintext pt = cc->MakePackedPlaintext(std::vector<int64_t>(value.size(), 1));
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);
    
    // Test External Product
    {
        auto res_ct = cc->EvalExternalProduct(rlwe_ct, rgsw_ct);
        
        Plaintext res;
        cc->Decrypt(keyPair.secretKey, res_ct, &res);
        res->SetLength(value.size());
    
        DEBUG_PRINT("Final result: " << res);
    
        const auto& result_slot = res->GetPackedValue();
        for (size_t i = 0; i < value.size(); i++) {
            ASSERT_EQ(value[i], result_slot[i]);
        }
    }

    // Test Internal Product
    {
        
    }
}

// Unit tests
TEST(RGSW, b0)    { RunTest({ 0 }); }
TEST(RGSW, b1)    { RunTest({ 1 }); }
TEST(RGSW, b00)   { RunTest({ 0, 0 }); }
TEST(RGSW, b01)   { RunTest({ 0, 1 }); }
TEST(RGSW, b10)   { RunTest({ 1, 0 }); }
TEST(RGSW, b11)   { RunTest({ 1, 1 }); }


int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
