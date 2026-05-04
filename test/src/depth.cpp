#define CENTER(integer, modulus) (((integer) > (modulus) / 2) ? ((integer % (2*modulus)) - (modulus)) : (integer))

// TODO: This is not a test per se, so move it out of the test/ directory

#include "core/context.h"
#include "core/helpers.h"
#include "core/params.h"
#include "core/rgsw.h"

#include "../cli_params.h"

#include <cstdint>
#include <iostream>
#include <utility>
#include <vector>


using namespace lbcrypto;

inline CCParams<CryptoContextRGSWBGV> GetParams() {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(test_cli::g_mult_depth.value_or(2));
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
    params.SetRingDim(test_cli::g_ring_dim.value_or(1 << 14));
    params.SetNumLargeDigits(2);

    // RGSW rows are built by hand → avoid per-level scaling (S_L = 1 needed).
    params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDMANUAL));

    // DEBUG_PRINT("Depth = " << params.GetMultiplicativeDepth());
    // DEBUG_PRINT("Ring Dim. = " << params.GetRingDim());
    // DEBUG_PRINT("Plaintext mod = " << params.GetPlaintextModulus());

    return params;
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
    constexpr int max_steps = 32;

    // (depth, dnum) combinations that the HYBRID key-switch setup accepts.
    // OpenFHE rejects e.g. (depth=3, dnum=3): 4 towers can't split into 3 digits.
    const std::vector<std::pair<uint32_t, uint32_t>> configs = {
        {2u, 2u}, {3u, 2u}, {4u, 2u}, {4u, 3u},
    };
    for (auto [depth, dnum] : configs) {
        const int ext = ProbeMaxExtChain_RNS(depth, dnum, max_steps);
        const int intp = ProbeMaxIntChain_RNS(depth, dnum, max_steps);
        std::cout << " [RNS depth=" << depth
                  << " dnum=" << dnum << "]"
                  << " ext-chain=" << ext
                  << " int-chain=" << intp
                  << std::endl;
    }
}

// Probe how far a chain of external products survives before noise corrupts the
// result. Returns the largest N for which 1, 2, …, N all decrypted correctly.
inline int ProbeMaxExtChain_Textbook(uint32_t mult_depth, uint64_t log_b, int max_steps) {
    auto params = GetParams();
    params.SetMultiplicativeDepth(mult_depth);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const size_t log_q = cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB();
    const size_t ell = log_q / log_b + 1;

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

inline int ProbeMaxIntChain_Textbook(uint32_t mult_depth, uint64_t log_b, int max_steps) {
    auto params = GetParams();
    params.SetMultiplicativeDepth(mult_depth);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const size_t log_q = cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB();
    const size_t ell = log_q / log_b + 1;

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
    constexpr int max_steps = 20;

    for (uint32_t depth : { 2u, 3u }) {
        for (auto log_b : std::vector<uint64_t>{ 30, 15, 10, 5 }) {
            const int ext = ProbeMaxExtChain_Textbook(depth, log_b, max_steps);
            const int intp = ProbeMaxIntChain_Textbook(depth, log_b, max_steps);
            std::cout << "  [textbook depth=" << depth << "]"
                      << " log_b=" << log_b
                      << " ext-chain=" << ext
                      << " int-chain=" << intp
                      << std::endl;
        }
    }
}


int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
