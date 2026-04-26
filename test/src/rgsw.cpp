#define TEST_INTERNAL_FUNCTIONS

#include "core/context.h"
#include "core/helpers.h"
#include "core/params.h"
#include "core/rgsw.h"

#include "../cli_params.h"

#include <cstdint>
#include <cmath>
#include <iostream>
#include <ranges>

using namespace lbcrypto;

/**
 * @brief Test the external product and internal product
 * @todo Maybe split into two separate files, for external and internal product?
 */
inline void RunTest(const std::vector<int64_t>& value) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(2);   // RGSW tests fix depth at 2; not tunable.
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
    params.SetRingDim(test_cli::g_ring_dim.value_or(16384));

    // RGSW rows are built by hand → avoid per-level scaling (S_L = 1 needed).
    params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDAUTO));
    params.SetGadgetBase(test_cli::g_gadget_base.value_or(30));                    // NOTE: base = 2^base
    params.SetGadgetDecomposition(test_cli::g_gadget_decomposition.value_or(4));   // TODO: set automatically
    
#if defined(DEBUG_LOGGING)
    std::cout << "Depth = " << params.GetMultiplicativeDepth() << std::endl;
    std::cout << "Ring Dim. = " << params.GetRingDim() << std::endl;
    std::cout << "Plaintext mod = " << params.GetPlaintextModulus() << std::endl;
#endif

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    
    auto rgsw_ct = cc->EncryptRGSW(keyPair.publicKey, value);
    
// #if defined(DEBUG_LOGGING)
//     auto ctxt = rgsw_ct[0];
//     auto& elements = ctxt->GetElements(); // Get elements (for multisum/encoding)
//     auto& allElements = elements[0].GetAllElements(); // Get RNS limbs
//     for (size_t i = 0; i < allElements.size(); ++i) {
//         std::cout << "Modulus " << i << ": " << allElements[i].GetModulus() << std::endl;
//     }
// #endif
    
#if defined(DEBUG_LOGGING)
    std::cout << "RGSW (decrypted): " << std::endl;
    PrintRGSW(cc, keyPair, rgsw_ct, value.size());
#endif

    Plaintext pt = cc->MakePackedPlaintext(value);
    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, pt);

    Plaintext res;
    auto res_ct = cc->EvalExternalProduct(rlwe_ct, rgsw_ct);
    cc->Decrypt(keyPair.secretKey, res_ct, &res);
    
#if defined(DEBUG_LOGGING)
    std::cout << "Final result: " << res << std::endl;
#endif

    const auto& result_slot = res->GetPackedValue();
    for(size_t i = 0; i < value.size(); i++) {
        ASSERT_EQ(value[i], result_slot[i]);
    }

    // RGSW(value) x RGSW(value) = RGSW(value x value)  (slot-wise)
    auto product = cc->EvalInternalProduct(rgsw_ct, rgsw_ct);

    // Extract via external product against RLWE(1...): result slot i = value[i]^2
    std::vector<int64_t> ones(value.size(), 1);
    auto rlwe_ones = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext(ones));

    res_ct = cc->EvalExternalProduct(rlwe_ones, product);
    cc->Decrypt(keyPair.secretKey, res_ct, &res);

    const auto& result_slot_sq = res->GetPackedValue();
    for(size_t i = 0; i < value.size(); i++) {
        ASSERT_EQ(value[i] * value[i], result_slot_sq[i]);
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