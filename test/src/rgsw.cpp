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
    params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDAUTO));

#if defined(DEBUG_LOGGING)
    std::cout << "Depth = " << params.GetMultiplicativeDepth() << std::endl;
    std::cout << "Ring Dim. = " << params.GetRingDim() << std::endl;
    std::cout << "Plaintext mod = " << params.GetPlaintextModulus() << std::endl;
#endif

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

#if defined(DEBUG_LOGGING)
    std::cout << "RGSW dnum = " << rgsw_ct.size() << std::endl;
#endif

    Plaintext pt = cc->MakePackedPlaintext(value);
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);

    Plaintext res;
    auto res_ct = cc->EvalExternalProduct(rlwe_ct, rgsw_ct);
    cc->Decrypt(keyPair.secretKey, res_ct, &res);
    res->SetLength(value.size());

#if defined(DEBUG_LOGGING)
    std::cout << "Final result: " << res << std::endl;
#endif

    const auto& result_slot = res->GetPackedValue();
    for (size_t i = 0; i < value.size(); i++) {
        ASSERT_EQ(value[i], result_slot[i]);
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
