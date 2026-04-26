#define TEST_INTERNAL_FUNCTIONS

#include "core/context.h"
#include "core/helpers.h"
#include "core/params.h"
#include "core/rgsw.h"

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
    // Note: n is not number of users but log(number of users)
    // const uint32_t n = value.size(); // bits
    // const uint32_t log_n = Log2(n);  // levels

    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(1);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);

    // Avoid per-level scaling factor 
    // RGSW rows are built by hand, so we need S_L = 1
    params.SetScalingTechnique(FIXEDAUTO);
    params.SetGadgetBase(30);               // NOTE: base = 2^base
    params.SetGadgetDecomposition(3);       // TODO: set automatically
    
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
    
#if defined(DEBUG_LOGGING)
    // // Assuming cc is your CryptoContext<DCRTPoly>
    // auto params = cc->GetCryptoParameters()->GetElementParams();
    // const std::vector<NativeInteger>& moduli = params.GetModuli();
    // for (const auto& q : moduli) {
    //     std::cout << "RNS Prime: " << q << std::endl;
    // }

    auto ctxt = rgsw_ct[0];
    auto& elements = ctxt->GetElements(); // Get elements (for multisum/encoding)
    auto& allElements = elements[0].GetAllElements(); // Get RNS limbs
    for (size_t i = 0; i < allElements.size(); ++i) {
        std::cout << "Modulus " << i << ": " << allElements[i].GetModulus() << std::endl;
    }
#endif
    
#if defined(DEBUG_LOGGING)
    std::cout << "G: " << std::endl;
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
}

// Basic test
TEST(ExternalProduct, b0)    { TestExternalProduct({ 0 }); }
TEST(ExternalProduct, b1)    { TestExternalProduct({ 1 }); }
TEST(ExternalProduct, b1010) { TestExternalProduct({ 1, 0, 1, 0 }); }

// Test internal product -> Eval against itself
inline void TestInternalProduct(const std::vector<int64_t>& value) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(2);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);

    // Avoid per-level scaling factor 
    // RGSW rows are built by hand, so we need S_L = 1
    params.SetScalingTechnique(FIXEDAUTO);
    params.SetGadgetBase(30);               // NOTE: base = 2^base
    params.SetGadgetDecomposition(4);       // TODO: set automatically
    
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
    
#if defined(DEBUG_LOGGING)
    std::cout << "RGSW (decrypted): " << std::endl;
    PrintRGSW(cc, keyPair, rgsw_ct, value.size());
#endif

    // RGSW(value) x RGSW(value) = RGSW(value x value)  (slot-wise)
    auto product = cc->EvalInternalProduct(rgsw_ct, rgsw_ct);

    // Extract via external product against RLWE(1...): result slot i = value[i]^2
    std::vector<int64_t> ones(value.size(), 1);
    auto rlwe_ones = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext(ones));

    Plaintext res;
    auto res_ct = cc->EvalExternalProduct(rlwe_ones, product);
    cc->Decrypt(keyPair.secretKey, res_ct, &res);

    const auto& result_slot = res->GetPackedValue();
    for(size_t i = 0; i < value.size(); i++) {
        ASSERT_EQ(value[i] * value[i], result_slot[i]);
    }
}

TEST(InternalProduct, b0)    { TestInternalProduct({ 0 }); }
TEST(InternalProduct, b1)    { TestInternalProduct({ 1 }); }
TEST(InternalProduct, b00)   { TestInternalProduct({ 0, 0 }); }
TEST(InternalProduct, b01)   { TestInternalProduct({ 0, 1 }); }
TEST(InternalProduct, b10)   { TestInternalProduct({ 1, 0 }); }
TEST(InternalProduct, b11)   { TestInternalProduct({ 1, 1 }); }