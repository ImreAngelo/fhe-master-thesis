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

// ─────────────────────────────────────────────────────────────────────────────
// Depth/noise invariance under chained RGSW operations.
//
// External/internal product implementations call SetLevel(x->GetLevel()) and
// SetNoiseScaleDeg(x->GetNoiseScaleDeg()) on their outputs (context.cpp). The
// level field never advances, so OpenFHE thinks no depth has been consumed —
// but each operation still adds noise, so eventually decryption fails. The
// "required depth" for a length-N chain is the smallest mult_depth at which
// the chain still decrypts.
//
// This test probes two things:
//   (a) Level/NoiseScaleDeg are unchanged across a chain (bookkeeping check).
//   (b) The largest chain length N that still decrypts at a given mult_depth.
//       Reported as a printout — used to compare against the textbook (non-RNS)
//       implementation in RGSW_Textbook.chain_no_depth_growth.
// ─────────────────────────────────────────────────────────────────────────────
inline int ProbeMaxExtChain_RNS(uint32_t mult_depth, uint32_t num_large_digits, int max_steps) {
    auto params = GetParams();
    params.SetMultiplicativeDepth(mult_depth);
    params.SetNumLargeDigits(num_large_digits);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    constexpr int64_t base = 2;
    const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());

    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({ 1 }));
    auto rgsw_c  = cc->EncryptRGSW(keyPair.secretKey, cc->MakePackedPlaintext({ base }));

    const auto initial_level = rlwe_ct->GetLevel();
    const auto initial_nsd   = rlwe_ct->GetNoiseScaleDeg();

    auto ct = rlwe_ct;
    for (int i = 1; i <= max_steps; ++i) {
        ct = cc->EvalExternalProduct(ct, rgsw_c);
        EXPECT_EQ(ct->GetLevel(), initial_level)
            << "RNS external product step " << i << " advanced level";
        EXPECT_EQ(ct->GetNoiseScaleDeg(), initial_nsd)
            << "RNS external product step " << i << " advanced NoiseScaleDeg";

        Plaintext res;
        cc->Decrypt(keyPair.secretKey, ct, &res);
        res->SetLength(1);

        int64_t v = 1;
        for (int k = 0; k < i; ++k) v = (v * base) % t;
        if (res->GetPackedValue()[0] != CENTER(v, t)) return i - 1;
    }
    return max_steps;
}

// Build RGSW(base^k) by chaining k-1 internal products, then check whether one
// external product onto RLWE(1) decrypts to base^k. Returns the largest k that
// still works.
inline int ProbeMaxIntChain_RNS(uint32_t mult_depth, uint32_t num_large_digits, int max_steps) {
    auto params = GetParams();
    params.SetMultiplicativeDepth(mult_depth);
    params.SetNumLargeDigits(num_large_digits);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    constexpr int64_t base = 2;
    const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());

    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({ 1 }));
    auto rgsw_c  = cc->EncryptRGSW(keyPair.secretKey, cc->MakePackedPlaintext({ base }));

    auto rgsw_chain = rgsw_c;
    int last_ok = 1;
    for (int k = 2; k <= max_steps; ++k) {
        rgsw_chain = cc->EvalInternalProduct(rgsw_chain, rgsw_c);

        auto out_ct = cc->EvalExternalProduct(rlwe_ct, rgsw_chain);
        Plaintext res;
        cc->Decrypt(keyPair.secretKey, out_ct, &res);
        res->SetLength(1);

        int64_t v = 1;
        for (int i = 0; i < k; ++i) v = (v * base) % t;
        if (res->GetPackedValue()[0] != CENTER(v, t)) return last_ok;
        last_ok = k;
    }
    return last_ok;
}

TEST(RGSW, chain_no_depth_growth) {
    constexpr int max_steps = 16;

    // (depth, dnum) combinations that the HYBRID key-switch setup accepts.
    // OpenFHE rejects e.g. (depth=3, dnum=3): 4 towers can't split into 3 digits.
    const std::vector<std::pair<uint32_t, uint32_t>> configs = {
        {2u, 2u}, {3u, 2u}, {4u, 2u}, {4u, 3u},
    };
    for (auto [depth, dnum] : configs) {
        const int ext = ProbeMaxExtChain_RNS(depth, dnum, max_steps);
        const int intp = ProbeMaxIntChain_RNS(depth, dnum, max_steps);
        std::cout << "  [RNS depth=" << depth
                  << " dnum=" << dnum << "] "
                  << "ext-chain=" << ext
                  << "  int-chain=" << intp
                  << std::endl;
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

// Probe how far a chain of external products survives before noise corrupts the
// result. Returns the largest N for which 1, 2, …, N all decrypted correctly.
inline int ProbeMaxExtChain_Textbook(uint32_t mult_depth, uint64_t log_b, size_t ell, int max_steps) {
    auto params = GetParams();
    params.SetMultiplicativeDepth(mult_depth);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    constexpr int64_t base = 2;
    const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());

    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({ 1 }));
    auto rgsw_c  = cc->Encrypt_Textbook(keyPair.publicKey, cc->MakePackedPlaintext({ base }), log_b, ell);

    auto ct = rlwe_ct;
    for (int i = 1; i <= max_steps; ++i) {
        ct = cc->EvalExternalProduct_Textbook(ct, rgsw_c, log_b);
        Plaintext res;
        cc->Decrypt(keyPair.secretKey, ct, &res);
        res->SetLength(1);

        int64_t v = 1;
        for (int k = 0; k < i; ++k) v = (v * base) % t;
        if (res->GetPackedValue()[0] != CENTER(v, t)) return i - 1;
    }
    return max_steps;
}

inline int ProbeMaxIntChain_Textbook(uint32_t mult_depth, uint64_t log_b, size_t ell, int max_steps) {
    auto params = GetParams();
    params.SetMultiplicativeDepth(mult_depth);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    constexpr int64_t base = 2;
    const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());

    auto rlwe_ct = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({ 1 }));
    auto rgsw_c  = cc->Encrypt_Textbook(keyPair.publicKey, cc->MakePackedPlaintext({ base }), log_b, ell);

    auto rgsw_chain = rgsw_c;
    int last_ok = 1;
    for (int k = 2; k <= max_steps; ++k) {
        rgsw_chain = cc->EvalInternalProduct_Textbook(rgsw_chain, rgsw_c, log_b);

        auto out_ct = cc->EvalExternalProduct_Textbook(rlwe_ct, rgsw_chain, log_b);
        Plaintext res;
        cc->Decrypt(keyPair.secretKey, out_ct, &res);
        res->SetLength(1);

        int64_t v = 1;
        for (int i = 0; i < k; ++i) v = (v * base) % t;
        if (res->GetPackedValue()[0] != CENTER(v, t)) return last_ok;
        last_ok = k;
    }
    return last_ok;
}

TEST(RGSW_Textbook, chain_no_depth_growth) {
    // Sweep the textbook gadget base. Smaller log_b means more digits but
    // smaller per-step noise — the classical noise/depth tradeoff.
    constexpr int max_steps = 16;

    for (uint32_t depth : { 2u, 3u }) {
        for (auto [log_b, ell] : std::vector<std::pair<uint64_t, size_t>>{ {30, 6}, {15, 12}, {10, 18} }) {
            const int ext = ProbeMaxExtChain_Textbook(depth, log_b, ell, max_steps);
            const int intp = ProbeMaxIntChain_Textbook(depth, log_b, ell, max_steps);
            std::cout << "  [textbook depth=" << depth
                      << " log_b=" << log_b
                      << " ell="   << ell << "] "
                      << "ext-chain=" << ext
                      << "  int-chain=" << intp
                      << std::endl;
        }
    }
}


int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
