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

    /* Depth Ext */ {
        const int64_t t = params.GetPlaintextModulus();

        int64_t expected = 1;

        const auto mult_pt = cc->MakeCoefPackedPlaintext({val});
        const auto initial_pt = cc->MakeCoefPackedPlaintext({expected});

        auto current = cc->Encrypt(keys.publicKey, initial_pt);

        for (int n = 1; n <= 64; ++n) {
            const auto mult = cc->EncryptRGSW(keys.publicKey, mult_pt);

            current = cc->EvalExternalProduct(current, mult);
            expected = (expected * val) % t;
            if (expected > t / 2) expected -= t;

            Plaintext decrypted;
            cc->Decrypt(keys.secretKey, current, &decrypted);

            const auto& coef = decrypted->GetCoefPackedValue();
            const int64_t got = coef.empty() ? 0 : coef[0];

            // decrypted->SetLength(1);
            // DEBUG_PRINT("EXTERNAL PRODUCT " << n << ": " << decrypted);

            if (got != expected) {
                DEBUG_PRINT("External product chain length: " << n - 1);
                ASSERT_GT(n, 1) << "Internal product could not be chained!";
                break;
            }
        }
    }

    /* Internal Product */ {
        DEBUG_TIMER("Internal Product");

        const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt);
        const auto prod = cc->EvalInternalProduct(rgsw, rgsw);

        const auto one = cc->MakeCoefPackedPlaintext({1});
        const auto identity = cc->Encrypt(keys.publicKey, one);
        const auto result = cc->EvalExternalProduct(identity, prod);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, result, &decrypted);
        decrypted->SetLength(1);

        DEBUG_PRINT("B: " << decrypted);
        DEBUG_PRINT("");

        const auto expected = cc->MakeCoefPackedPlaintext({val * val});
        ASSERT_EQ(decrypted, expected);
    }

    /* Depth - TODO: Refactor */ {
        const int64_t t = params.GetPlaintextModulus();

        const auto mult  = val;
        const auto pt3   = cc->MakeCoefPackedPlaintext({mult});
        const auto rgsw2 = cc->EncryptRGSW(keys.publicKey, pt3);

        // val = RGSW(1) initially; RLWE(1) used as the left operand for verification.
        const auto pt1   = cc->MakeCoefPackedPlaintext({1});
        const auto rlwe1 = cc->Encrypt(keys.publicKey, pt1);
        auto current = cc->EncryptRGSW(keys.publicKey, pt1);

        // 2^n mod t, kept centered in (-t/2, t/2].
        int64_t expected = 1;

        for (int n = 1; n <= 64; ++n) {
            current = cc->EvalInternalProduct(rgsw2, current);
            expected = (expected * mult) % t;
            if (expected > t / 2) expected -= t;

            const auto res = cc->EvalExternalProduct(rlwe1, current);
            Plaintext decrypted;
            cc->Decrypt(keys.secretKey, res, &decrypted);

            const auto& coef = decrypted->GetCoefPackedValue();
            const int64_t got = coef.empty() ? 0 : coef[0];

            if (got != expected) {
                DEBUG_PRINT("Chain length: " << n - 1);
                ASSERT_GT(n, 1) << "Internal product could not be chained!";
                return;
            }
        }

        DEBUG_PRINT("Chained 64 internal products!");
    }
};
