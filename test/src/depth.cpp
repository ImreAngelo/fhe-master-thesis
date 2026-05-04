#define CENTER(integer, modulus) (((integer) > (modulus) / 2) ? ((integer % (2*modulus)) - (modulus)) : (integer))

// TODO: This is not a test per se, so move it out of the test/ directory

#include "core/context.h"
#include "core/helpers.h"
#include "core/params.h"
#include "core/rgsw.h"

#include "../cli_params.h"

#include <cstdint>
#include <iostream>

#include "utils/timer.h"
#define TIMER(label) utils::Timer t(label)
#define PRINT(text) std::cout << text << " "

using namespace lbcrypto;

inline CCParams<CryptoContextRGSWBGV> GetParams() {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(test_cli::g_mult_depth.value_or(2));
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
    params.SetRingDim(test_cli::g_ring_dim.value_or(1 << 14));
    params.SetNumLargeDigits(2);

    // RGSW rows are built by hand → avoid per-level scaling (S_L = 1 needed).
    params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDMANUAL));
    params.SetSecurityLevel(HEStd_NotSet);

    return params;
}

// ─────────────────────────────────────────────────────────────────────────────
// Find the minimum mult_depth that still decrypts after N chained internal
// products. Internal/external product implementations don't advance the level
// field, so OpenFHE thinks no depth was consumed — but each call adds noise,
// and at some point decryption fails. We sweep depth upwards and report the
// first one where the chain survives.
// ─────────────────────────────────────────────────────────────────────────────

// Number of EvalInternalProduct calls in the chain. Starting from RGSW(base),
// after kInternalChainN calls the chain encrypts base^(kInternalChainN + 1).
constexpr int      kInternalChainN = 18;
constexpr uint32_t kMaxDepthSweep  = 30;

// Probe the longest chain (up to max_chain calls to EvalInternalProduct) that
// still decrypts at this depth. Returns the largest N for which N internal
// products followed by one external product onto RLWE(1) decrypts to base^(N+1).
inline int ProbeMaxIntChain_RNS(uint32_t mult_depth, uint32_t num_large_digits, int max_chain) {
    auto params = GetParams();
    params.SetMultiplicativeDepth(mult_depth);
    // params.SetNumLargeDigits(num_large_digits);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

    constexpr int64_t base = 2;
    const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());

    auto rlwe_ct    = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({ 1 }));
    auto rgsw_c     = cc->EncryptRGSW(keyPair.secretKey, cc->MakePackedPlaintext({ base }));
    auto rgsw_chain = rgsw_c;

    int last_ok = 0;
    for (int n = 1; n <= max_chain; ++n) {
        rgsw_chain = cc->EvalInternalProduct(rgsw_chain, rgsw_c);

        auto out_ct = cc->EvalExternalProduct(rlwe_ct, rgsw_chain);
        Plaintext res;
        cc->Decrypt(keyPair.secretKey, out_ct, &res);
        res->SetLength(1);

        int64_t v = 1;
        for (int i = 0; i < n + 1; ++i) v = (v * base) % t;
        if (res->GetPackedValue()[0] != CENTER(v, t)) return last_ok;
        last_ok = n;
    }
    return last_ok;
}

inline int ProbeMaxIntChain_Textbook(uint32_t mult_depth, uint64_t log_b, int max_chain) {
    auto params = GetParams();
    params.SetMultiplicativeDepth(mult_depth);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const size_t log_q = cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB();
    const size_t ell = log_q / log_b + 1;

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

    constexpr int64_t base = 2;
    const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());

    auto rlwe_ct    = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({ 1 }));
    auto rgsw_c     = cc->Encrypt_Textbook(keyPair.publicKey, cc->MakePackedPlaintext({ base }), log_b, ell);
    auto rgsw_chain = rgsw_c;

    int last_ok = 0;
    for (int n = 1; n <= max_chain; ++n) {
        rgsw_chain = cc->EvalInternalProduct_Textbook(rgsw_chain, rgsw_c, log_b);

        auto out_ct = cc->EvalExternalProduct_Textbook(rlwe_ct, rgsw_chain, log_b);
        Plaintext res;
        cc->Decrypt(keyPair.secretKey, out_ct, &res);
        res->SetLength(1);

        int64_t v = 1;
        for (int i = 0; i < n + 1; ++i) v = (v * base) % t;
        if (res->GetPackedValue()[0] != CENTER(v, t)) return last_ok;
        last_ok = n;
    }
    return last_ok;
}

TEST(RGSW, depth_for_N_internal_products) {
    constexpr uint32_t dnum = 2;  // compatible with all swept depths

    uint32_t found = 0;
    for (uint32_t depth = 2; depth <= kMaxDepthSweep; ++depth) {
        TIMER(" [RNS dnum=" + std::to_string(dnum) + " depth=" + std::to_string(depth) + "]");
        const int max_chain = ProbeMaxIntChain_RNS(depth, dnum, kInternalChainN);
        PRINT("max length " + std::to_string(max_chain));
        if (max_chain >= kInternalChainN) { found = depth; break; }
    }

    std::cout << " [RNS dnum=" << dnum << "]"
              << " min depth for N=" << kInternalChainN << " internal products: ";
    if (found > 0) std::cout << found << std::endl;
    else           std::cout << "not found in [2, " << kMaxDepthSweep << "]" << std::endl;
    EXPECT_GT(found, 0u);
}

TEST(RGSW_Textbook, depth_for_N_internal_products) {
    constexpr uint64_t log_b = 15;  // log_b doesn't really matter for this sweep

    uint32_t found = 0;
    for (uint32_t depth = 2; depth <= kMaxDepthSweep; ++depth) {
        TIMER(" [textbook log_b=" + std::to_string(log_b) + " depth=" + std::to_string(depth) + "]");
        const int max_chain = ProbeMaxIntChain_Textbook(depth, log_b, kInternalChainN);
        PRINT("max length " + std::to_string(max_chain));
        if (max_chain >= kInternalChainN) { found = depth; break; }
    }

    std::cout << " [textbook log_b=" << log_b << "]"
              << " min depth for N=" << kInternalChainN << " internal products: ";
    if (found > 0) std::cout << found << std::endl;
    else           std::cout << "not found in [2, " << kMaxDepthSweep << "]" << std::endl;
    EXPECT_GT(found, 0u);
}


int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
