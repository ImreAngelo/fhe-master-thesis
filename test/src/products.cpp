#include "core/context.h"
#include "core/types.h"
#include "gtest/gtest.h"
#include "key/keypair.h"
#include "lattice/hal/lat-backend.h"
#include "params.h"
#include <gtest/gtest.h>
#include <cstddef>
#include <functional>

namespace spar::test {

using namespace lbcrypto;

struct TestCase {
    std::string label;
    std::function<ExtendedContext()> make;
    enum Packing { COEF = 0x0, SIMD = 0x1 } packing;
    bool isHybrid = false;
};

class Products : public ::testing::TestWithParam<TestCase> {
   protected:
    ExtendedContext cc;
    KeyPair<DCRTPoly> keys;
    Plaintext pt_one;

    static constexpr int64_t base_value = 1;

    void SetUp() override {
        cc = GetParam().make();
        cc->Enable(PKE);

        keys = cc->KeyGen();

        // TODO: Streamline
        if (GetParam().isHybrid) {
            cc->SetExtendedKey(keys);
        }

        pt_one = MakePlaintext({1});
    }

    Plaintext Decrypt(RLWE ct, size_t len = 1) const {
        Plaintext dec;
        cc->Decrypt(keys.secretKey, ct, &dec);
        dec->SetLength(len);
        return dec;
    };

    Plaintext MakePlaintext(const std::vector<int64_t>& value) const {
        // clang-format off
        return (GetParam().packing == TestCase::COEF) 
            ? cc->MakeCoefPackedPlaintext(value)
            : cc->MakePackedPlaintext(value);
        // clang-format on
    }
};

#pragma region TESTS

TEST_P(Products, External) {
    const auto expected = MakePlaintext({base_value * base_value});
    const auto rlwe = cc->Encrypt(keys.publicKey, pt_one);
    const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt_one);

    const auto prod = cc->EvalExternalProduct(rlwe, rgsw);
    const auto result = Decrypt(prod);

    ASSERT_EQ(result, expected);
};

TEST_P(Products, Internal) {
    // TODO: Clean up + test mixed product in place of internal product
    if (GetParam().isHybrid) return;

    const auto expected = MakePlaintext({base_value * base_value});
    const auto rlwe = cc->Encrypt(keys.publicKey, pt_one);
    const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt_one);

    const auto prod = cc->EvalInternalProduct(rgsw, rgsw);
    const auto result = Decrypt(cc->EvalExternalProduct(rlwe, prod));

    ASSERT_EQ(result, expected);
};

#pragma endregion TESTS

#define SETUP_TEST_SUITE(prefix, ...) \
    INSTANTIATE_TEST_SUITE_P(prefix, Products, ::testing::Values(__VA_ARGS__), [](const auto& info) { return info.param.label; })

using params::Set;

// clang-format off
// Standard gadget
SETUP_TEST_SUITE(BV, 
    TestCase{"standard", [] { return GenContextBV(Make(Set::Standard), 3); }},
    TestCase{"simd", [] { return GenContextBV(Make(Set::Standard), 3); }, TestCase::SIMD}
);

// Hybrid gadget
SETUP_TEST_SUITE(Hybrid, 
    TestCase{"standard", [] { return GenContextHybrid(Make(Set::Standard)); }, TestCase::Packing::COEF, true},
    TestCase{"simd", [] { return GenContextHybrid(Make(Set::Standard)); }, TestCase::Packing::SIMD, true}
);
// clang-format on

}  // namespace spar::test