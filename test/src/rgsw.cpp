#define TEST_INTERNAL_FUNCTIONS

#include "core/context.h"
#include "core/helpers.h"
#include "core/params.h"
#include "core/rgsw.h"

#include <cstdint>
#include <cmath>
#include <iostream>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>

using namespace lbcrypto;

// CLI overrides set in main(); std::nullopt use the per-test hardcoded default.
namespace {
    std::optional<uint32_t> g_mult_depth;
    std::optional<uint32_t> g_plaintext_modulus;
    std::optional<uint32_t> g_ring_dim;
    std::optional<uint32_t> g_gadget_base;
    std::optional<uint32_t> g_gadget_decomposition;
}

/**
 * @brief Test the external product and internal product
 * @todo Maybe split into two separate files, for external and internal product?
 */
inline void RunTest(const std::vector<int64_t>& value) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(g_mult_depth.value_or(2));
    params.SetPlaintextModulus(g_plaintext_modulus.value_or(65537));
    params.SetRingDim(g_ring_dim.value_or(16384));

    // Avoid per-level scaling factor
    params.SetScalingTechnique(FIXEDAUTO);
    params.SetGadgetBase(g_gadget_base.value_or(30));                    // NOTE: base = 2^base
    params.SetGadgetDecomposition(g_gadget_decomposition.value_or(4));   // TODO: set automatically
    
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


// GoogleTest entry point that recognises RGSW tuning flags
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    auto parse_uint = [](std::string_view value, std::optional<uint32_t>& slot, std::string_view name) {
        try {
            slot = static_cast<uint32_t>(std::stoul(std::string(value)));
        } catch (const std::exception&) {
            std::cerr << "test-rgsw: invalid value for --" << name << ": " << value << "\n";
            std::exit(2);
        }
    };

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        const auto eq = arg.find('=');
        if (arg.substr(0, 2) != "--" || eq == std::string_view::npos) {
            std::cerr << "test-rgsw: unrecognised argument: " << arg << "\n";
            return 2;
        }
        const auto name  = arg.substr(2, eq - 2);
        const auto value = arg.substr(eq + 1);

        if      (name == "mult_depth")           parse_uint(value, g_mult_depth,           name);
        else if (name == "plaintext_modulus")    parse_uint(value, g_plaintext_modulus,    name);
        else if (name == "ring_dim")             parse_uint(value, g_ring_dim,             name);
        else if (name == "gadget_base")          parse_uint(value, g_gadget_base,          name);
        else if (name == "gadget_decomposition") parse_uint(value, g_gadget_decomposition, name);
        else {
            std::cerr << "test-rgsw: unknown flag --" << name << "\n";
            return 2;
        }
    }

    return RUN_ALL_TESTS();
}