#define TEST_INTERNAL_FUNCTIONS
#include "core/context.h"

using namespace Core;

TEST(BV, HPS) {
    constexpr int64_t val = 1;
    const std::vector<int64_t> value{val};

    auto params = params::Small<CryptoContextBGVRNS>();
    // params.SetRingDim(16); // For printing

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    const auto keys = cc->KeyGen();

    const auto bv = HPSContext(cc, 6); // Internal chain: 2 -> 1, 4 -> 2, 6+ -> 3
    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);

    /* Encrypt */ {
        DEBUG_TIMER("Encrypt");
        const auto rgsw = bv.EncryptRGSW(keys.publicKey, pt);
    }

    /* External Product */ {
        const auto rgsw = bv.EncryptRGSW(keys.publicKey, pt);
        const auto rlwe = cc->Encrypt(keys.publicKey, pt);
        
        // DEBUG_PRINT("\nRGSW:");
        // for(const auto& row : rgsw) {
        //     Plaintext dec;
        //     cc->Decrypt(keys.secretKey, row, &dec);
        //     dec->SetLength(16);
        //     DEBUG_PRINT(dec);
        // }
        // DEBUG_PRINT("");
        
        DEBUG_TIMER("External Product");
        const auto result = bv.EvalExternalProduct(rlwe, rgsw);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, result, &decrypted);
        decrypted->SetLength(1);

        DEBUG_PRINT("A: " << decrypted);
        DEBUG_PRINT("");

        const auto expected = cc->MakeCoefPackedPlaintext({val * val});
        ASSERT_EQ(decrypted, expected);
    }

    /* Internal Product */ {
        DEBUG_TIMER("Internal Product");
        
        const auto rgsw = bv.EncryptRGSW(keys.publicKey, pt);
        const auto prod = bv.EvalInternalProduct(rgsw, rgsw);

        const auto one = cc->MakeCoefPackedPlaintext({1});
        const auto identity = cc->Encrypt(keys.publicKey, one);
        const auto result = bv.EvalExternalProduct(identity, prod);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, result, &decrypted);
        decrypted->SetLength(1);
        
        DEBUG_PRINT("B: " << decrypted);
        DEBUG_PRINT("");
        
        const auto expected = cc->MakeCoefPackedPlaintext({val * val});
        ASSERT_EQ(decrypted, expected);
    }

    /* Depth */ {
        const int64_t t = params.GetPlaintextModulus();

        // The fixed multiplier applied each round.
        // Noise is scaled by value so keep it binary.
        const auto mult  = val;
        const auto pt3   = cc->MakeCoefPackedPlaintext({mult});
        const auto rgsw2 = bv.EncryptRGSW(keys.publicKey, pt3, true);

        // val = RGSW(1) initially; RLWE(1) used as the left operand for verification.
        const auto pt1   = cc->MakeCoefPackedPlaintext({1});
        const auto rlwe1 = cc->Encrypt(keys.publicKey, pt1);
        auto current = bv.EncryptRGSW(keys.publicKey, pt1);

        // 2^n mod t, kept centered in (-t/2, t/2].
        int64_t expected = 1;

        for (int n = 1; n <= 64; ++n) {
            current = bv.EvalInternalProduct(rgsw2, current);
            expected = (expected * mult) % t;
            if (expected > t / 2) expected -= t;

            const auto res = bv.EvalExternalProduct(rlwe1, current);
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
}
