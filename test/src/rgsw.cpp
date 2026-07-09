#include "core/context.h"
#include <functional>
#include <string>

namespace spar::test {

using namespace lbcrypto;

struct SchemeCase {
    std::string name;
    std::function<ExtendedContext()> make;
};

class RGSW : public ::testing::TestWithParam<SchemeCase> {
   protected:
    ExtendedContext cc;
    KeyPair<DCRTPoly> keys;
    Plaintext pt_one;

    // Noise scales with message magnitude; assume binary plaintexts
    static constexpr int64_t kVal = 1;

    void SetUp() override {
        cc = GetParam().make();
        cc->Enable(PKE);
        // cc->Enable(LEVELEDSHE);

        keys = cc->KeyGen();
        pt_one = cc->MakeCoefPackedPlaintext({kVal});
    }

    int64_t PlaintextModulus() const { return cc->GetCryptoParameters()->GetPlaintextModulus(); }

    int64_t FirstCoef(const Plaintext& pt) const {
        const auto& coef = pt->GetCoefPackedValue();
        return coef.empty() ? 0 : coef[0];
    }
};

TEST_P(RGSW, Encrypt) {
    DEBUG_TIMER("Encrypt");
    const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt_one);
    (void)rgsw;
}

TEST_P(RGSW, ExternalProduct) {
    const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt_one);
    const auto rlwe = cc->Encrypt(keys.publicKey, pt_one);

    DEBUG_TIMER("External Product");
    const auto result = cc->EvalExternalProduct(rlwe, rgsw);

    Plaintext decrypted;
    cc->Decrypt(keys.secretKey, result, &decrypted);
    decrypted->SetLength(1);

    const auto expected = cc->MakeCoefPackedPlaintext({kVal * kVal});
    ASSERT_EQ(decrypted, expected);
}

TEST_P(RGSW, InternalProduct) {
    DEBUG_TIMER("Internal Product");

    const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt_one);
    const auto prod = cc->EvalInternalProduct(rgsw, rgsw);

    const auto identity = cc->Encrypt(keys.publicKey, pt_one);
    const auto result = cc->EvalExternalProduct(identity, prod);

    Plaintext decrypted;
    cc->Decrypt(keys.secretKey, result, &decrypted);
    decrypted->SetLength(1);

    const auto expected = cc->MakeCoefPackedPlaintext({kVal * kVal});
    ASSERT_EQ(decrypted, expected);
}

TEST_P(RGSW, ExternalProductChains) {
    const int64_t t = PlaintextModulus();
    const auto mult_pt = cc->MakeCoefPackedPlaintext({kVal});

    auto current = cc->Encrypt(keys.publicKey, pt_one);
    int64_t expected = 1;
    int last_ok = 0;

    for (int n = 1; n <= 64; ++n) {
        const auto mult = cc->EncryptRGSW(keys.publicKey, mult_pt);
        current = cc->EvalExternalProduct(current, mult);

        expected = (expected * kVal) % t;
        if (expected > t / 2) expected -= t;

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, current, &decrypted);
        if (FirstCoef(decrypted) != expected) break;
        last_ok = n;
    }

    DEBUG_PRINT("External product chain length: " << last_ok);
    ASSERT_GT(last_ok, 0) << "Could not chain even one external product";
}

TEST_P(RGSW, InternalProductChains) {
    const int64_t t = PlaintextModulus();
    const auto mult_pt = cc->MakeCoefPackedPlaintext({kVal});
    const auto rgsw_mult = cc->EncryptRGSW(keys.publicKey, mult_pt);
    const auto rlwe_one = cc->Encrypt(keys.publicKey, pt_one);

    auto current = cc->EncryptRGSW(keys.publicKey, pt_one);
    int64_t expected = 1;
    int last_ok = 0;

    for (int n = 1; n <= 64; ++n) {
        current = cc->EvalInternalProduct(rgsw_mult, current);

        expected = (expected * kVal) % t;
        if (expected > t / 2) expected -= t;

        const auto res = cc->EvalExternalProduct(rlwe_one, current);
        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, res, &decrypted);
        if (FirstCoef(decrypted) != expected) break;
        last_ok = n;
    }

    DEBUG_PRINT("Internal product chain length: " << last_ok);
    ASSERT_GT(last_ok, 0) << "Could not chain even one internal product";
}

INSTANTIATE_TEST_SUITE_P(Scheme, RGSW,
                         ::testing::Values(SchemeCase{"BV", [] { return GenContextBV(params::Small(), /*ell=*/2); }},
                                           // SchemeCase{"Hybrid", [] { return GenContextHybrid(params::Small()); }},
                                           SchemeCase{"BV_large", [] { return GenContextBV(params::Large(), /*ell=*/3); }}
                                           // SchemeCase{"Hybrid_large", [] { return GenContextHybrid(params::Large()); }}
                                           ),
                         [](const auto& info) { return info.param.name; });

}  // namespace spar::test
