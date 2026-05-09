#include "core/context.h"
#include "core/params.h"

#include "../cli_params.h"

#include <cstdint>
#include <iostream>

using namespace lbcrypto;

inline void RunDepthTest(uint32_t mult_depth, int max = 500) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(mult_depth);
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(1 << 8));
    params.SetRingDim(test_cli::g_ring_dim.value_or(1 << 11));
    params.SetSecurityLevel(HEStd_NotSet);
    params.SetMaxRelinSkDeg(0);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

    const int64_t log_b = test_cli::g_gadget_base.value_or(15);
    const size_t log_q  = cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB();
    const size_t ell    = log_q / log_b + 1;

    auto rgsw_one = cc->EncryptRGSW(keyPair.publicKey, cc->MakeCoefPackedPlaintext({3}), log_b, ell);
    auto rlwe_one = cc->Encrypt(keyPair.publicKey, cc->MakeCoefPackedPlaintext({1}));

    const int64_t t = params.GetPlaintextModulus();

    // Returns the centered representative of x in [-t/2, t/2).
    auto centeredMod = [t](int64_t x) -> int64_t {
        x = ((x % t) + t) % t;
        return x >= t / 2 ? x - t : x;
    };

    auto decryptsTo = [&](const Ciphertext<DCRTPoly>& ct, int64_t expected) {
        Plaintext res;
        cc->Decrypt(keyPair.secretKey, ct, &res);

        res->SetLength(4);
        DEBUG_PRINT(res);

        return res->GetCoefPackedValue()[0] == centeredMod(expected);
    };

    int ext_count = 0;
    {
        auto chain = rlwe_one;
        int64_t expected = 3; // rlwe_one(1) * rgsw_one(3) = 3 after first mult
        while (ext_count < max) {
            chain = cc->EvalExternalProduct(chain, rgsw_one, log_b);
            if (!decryptsTo(chain, expected)) break;
            ++ext_count;
            expected = (expected * 3) % t;
            DEBUG_PRINT("[External Product] " << ext_count << " chain pass");
        }
    }

    int int_count = 0;
    {
        auto chain = rgsw_one;
        int64_t expected = 9; // rlwe_one(1) * rgsw_one^2(9) = 9 after first internal product
        while (int_count < max) {
            chain = cc->EvalInternalProduct(chain, rgsw_one, log_b);
            if (!decryptsTo(cc->EvalExternalProduct(rlwe_one, chain, log_b), expected)) break;
            ++int_count;
            expected = (expected * 3) % t;
            DEBUG_PRINT("[Internal Product] " << int_count << " chain pass");
        }
    }

    std::cout << "depth=" << mult_depth
              << "  external_products=" << ext_count
              << "  internal_products=" << int_count << std::endl;

    EXPECT_GT(ext_count, 0) << "no external products survived at depth " << mult_depth;
    EXPECT_GT(int_count, 0) << "no internal products survived at depth " << mult_depth;
}

TEST(Depth, d3) { RunDepthTest(3); }
TEST(Depth, d4) { RunDepthTest(4); }

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
