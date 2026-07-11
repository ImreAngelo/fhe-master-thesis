#include "core/context.h"
#include "core/utils/noise.h"
#include <functional>
#include <string>

namespace spar::test {

using namespace lbcrypto;

const int CHAIN_ITERATIONS = 1000;

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
        cc->SetExtendedKey(keys);  // publishes QP key material (no-op for BV)
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

TEST_P(RGSW, PublicExternalProduct) {
    const auto rgsw = cc->MakePublicRGSW(keys.publicKey, pt_one);
    const auto rlwe = cc->Encrypt(keys.publicKey, pt_one);

    DEBUG_TIMER("Public External Product");
    const auto result = cc->EvalExternalProduct(rlwe, rgsw);

    Plaintext decrypted;
    cc->Decrypt(keys.secretKey, result, &decrypted);
    decrypted->SetLength(1);

    const auto expected = cc->MakeCoefPackedPlaintext({kVal * kVal});
    ASSERT_EQ(decrypted, expected);
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

    PRINT_MAX_NOISE(cc, result, keys.secretKey);

    const auto expected = cc->MakeCoefPackedPlaintext({kVal * kVal});
    ASSERT_EQ(decrypted, expected);
}

TEST_P(RGSW, Add) {
    const auto a = cc->EncryptRGSW(keys.publicKey, pt_one);
    const auto b = cc->EncryptRGSW(keys.publicKey, pt_one);

    DEBUG_TIMER("Add");
    const auto sum = cc->EvalAddRGSW(a, b);

    // The sum must still act as a valid RGSW(2) in an external product
    const auto rlwe_one = cc->Encrypt(keys.publicKey, pt_one);
    const auto result = cc->EvalExternalProduct(rlwe_one, sum);

    Plaintext decrypted;
    cc->Decrypt(keys.secretKey, result, &decrypted);
    ASSERT_EQ(FirstCoef(decrypted), 2 * kVal);
}

TEST_P(RGSW, Sub) {
    const auto zero = cc->EncryptRGSW(keys.publicKey, cc->MakeCoefPackedPlaintext({0}));
    const auto one = cc->EncryptRGSW(keys.publicKey, pt_one);

    DEBUG_TIMER("Sub");
    const auto diff = cc->EvalSubRGSW(zero, one);

    // 0 - 1 = -1 catches sign errors that a symmetric difference would hide
    const auto rlwe_one = cc->Encrypt(keys.publicKey, pt_one);
    const auto result = cc->EvalExternalProduct(rlwe_one, diff);

    Plaintext decrypted;
    cc->Decrypt(keys.secretKey, result, &decrypted);
    ASSERT_EQ(FirstCoef(decrypted), -kVal);
}

TEST_P(RGSW, MultPlaintext) {
    const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt_one);
    const auto pt_three = cc->MakeCoefPackedPlaintext({3});

    DEBUG_TIMER("Mult Plaintext");
    const auto prod = cc->EvalMultRGSW(rgsw, pt_three);

    const auto rlwe_one = cc->Encrypt(keys.publicKey, pt_one);
    const auto result = cc->EvalExternalProduct(rlwe_one, prod);

    Plaintext decrypted;
    cc->Decrypt(keys.secretKey, result, &decrypted);
    ASSERT_EQ(FirstCoef(decrypted), 3 * kVal);
}

TEST_P(RGSW, ExternalProductChains) {
    const int64_t t = PlaintextModulus();
    const auto mult_pt = cc->MakeCoefPackedPlaintext({kVal});

    auto current = cc->Encrypt(keys.publicKey, pt_one);
    int64_t expected = 1;
    int last_ok = 0;

    RECORD_START("results/external_chain_" + GetParam().name + ".csv", "n,msb,noise");
    for (int n = 1; n <= CHAIN_ITERATIONS; ++n) {
        const auto mult = cc->EncryptRGSW(keys.publicKey, mult_pt);
        current = cc->EvalExternalProduct(current, mult);

        RECORD_MAX_NOISE(n, cc, current, keys.secretKey);
        // PRINT_MAX_NOISE(cc, current, keys.secretKey);

        expected = (expected * kVal) % t;
        if (expected > t / 2) expected -= t;

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, current, &decrypted);
        if (FirstCoef(decrypted) != expected) break;
        last_ok = n;
    }
    RECORD_END();

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

    RECORD_START("results/internal_chain_" + GetParam().name + ".csv", "n,msb,noise");
    for (int n = 1; n <= CHAIN_ITERATIONS; ++n) {
        current = cc->EvalInternalProduct(current, rgsw_mult);
        const auto res = cc->EvalExternalProduct(rlwe_one, current);

        RECORD_MAX_NOISE(n, cc, res, keys.secretKey);
        PRINT_MAX_NOISE(cc, res, keys.secretKey);

        expected = (expected * kVal) % t;
        if (expected > t / 2) expected -= t;

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, res, &decrypted);

        if (FirstCoef(decrypted) != expected) break;
        last_ok = n;
    }
    RECORD_END();

    DEBUG_PRINT("Internal product chain length: " << last_ok);
    ASSERT_GT(last_ok, 0) << "Could not chain even one internal product";
}

INSTANTIATE_TEST_SUITE_P(Scheme, RGSW,
                         ::testing::Values(SchemeCase{"BV_Small", [] { return GenContextBV(params::Small(), /*ell=*/2); }},
                                           SchemeCase{"Hybrid", [] { return GenContextHybrid(params::Small(true)); }},
                                           SchemeCase{"BV_Large", [] { return GenContextBV(params::Large(), /*ell=*/3); }},
                                           SchemeCase{"Hybrid_large", [] { return GenContextHybrid(params::Large()); }}
                                           ),
                         [](const auto& info) { return info.param.name; });

}  // namespace spar::test
