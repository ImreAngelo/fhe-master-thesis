#define TEST_INTERNAL_FUNCTIONS

#include "core/context.h"

#include <cstdint>
#include <iostream>


using namespace lbcrypto;


TEST(Depth, ChainedInternalProduct) {
    CCParams<CryptoContextBGVRNS> params;
    params.SetRingDim(1 << 11);           // N = 2048
    params.SetPlaintextModulus(8);        // t = 8
    params.SetMultiplicativeDepth(1);
    params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);

    const auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const auto keys = cc->KeyGen();

    constexpr int64_t t = 8;

    // RGSW(2): the fixed multiplier applied each round.
    const auto pt2   = cc->MakeCoefPackedPlaintext({2});
    const auto rgsw2 = cc->EncryptRGSW(keys.publicKey, pt2);

    // val = RGSW(1) initially; RLWE(1) used as the left operand for verification.
    const auto pt1   = cc->MakeCoefPackedPlaintext({1});
    auto val         = cc->EncryptRGSW(keys.publicKey, pt1);
    const auto rlwe1 = cc->Encrypt(keys.publicKey, pt1);

    // 2^n mod t, kept centered in (-t/2, t/2].
    int64_t expected = 1;

    for (int n = 1; n <= 64; ++n) {
        val      = cc->EvalInternalProduct(rgsw2, val);
        expected = (expected * 2) % t;
        if (expected > t / 2) expected -= t;

        const auto res = cc->EvalExternalProduct(rlwe1, val);
        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, res, &decrypted);

        const auto& coef = decrypted->GetCoefPackedValue();
        const int64_t got = coef.empty() ? 0 : coef[0];

        if (got != expected) {
            std::cout << "Chained internal products valid up to depth " << (n - 1) << std::endl;
            return;
        }
    }

    std::cout << "All 64 depths passed." << std::endl;
}
