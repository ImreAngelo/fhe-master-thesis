#include "scheme/context-bv.h"


TEST(RGSW, Classes) {
    using namespace spar;
    using namespace lbcrypto;

    auto params = params::Small<CryptoContextBV>();
    params.SetEll(2);

    const auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const auto keys = cc->KeyGen();

    // The noise is scaled by m, so the most valid tests are with binary val
    constexpr int64_t val = 1;

    const Plaintext pt = cc->MakeCoefPackedPlaintext({val});

    /* Encrypt */ {
        DEBUG_TIMER("Encrypt");
        const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt);
    }

    /* External Product */ {
        const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt);
        const auto rlwe = cc->Encrypt(keys.publicKey, pt);

        DEBUG_TIMER("External Product");
        const auto result = cc->EvalExternalProduct(rlwe, rgsw);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, result, &decrypted);
        decrypted->SetLength(1);

        DEBUG_PRINT("A: " << decrypted);
        DEBUG_PRINT("");

        const auto expected = cc->MakeCoefPackedPlaintext({val * val});
        ASSERT_EQ(decrypted, expected);
    }
};
