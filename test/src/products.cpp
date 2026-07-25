#include "core/context.h"
#include "core/types.h"
#include "key/keypair.h"
#include "lattice/hal/lat-backend.h"
#include "spar/params.h"
#include <gtest/gtest.h>
#include <cstddef>
#include <functional>
#include <ostream>

namespace spar::test {

using namespace lbcrypto;

struct TestCase {
    std::string label;
    std::function<ExtendedContext()> make;
    enum Packing { COEF = 0x0, SIMD = 0x1 } packing = COEF;
    bool isHybrid = false;
};

/// Without this, gtest has no way to print a TestCase and falls back to dumping
/// the raw object bytes into every failure message for a parameterized case.
/// The label is already the test name's suffix, so print what the name does not
/// carry.
void PrintTo(const TestCase& tc, std::ostream* os) {
    *os << "packing=" << (tc.packing == TestCase::SIMD ? "simd" : "coef") << ", scheme=" << (tc.isHybrid ? "hybrid" : "bv");
}

class Products : public ::testing::TestWithParam<TestCase> {
   protected:
    ExtendedContext cc;
    KeyPair<DCRTPoly> keys;
    Plaintext pt_one;

    static constexpr int64_t base_value = 1;

    void SetUp() override {
        cc = GetParam().make();
        keys = utils::MakeKeys(cc);  // SetExtendedKey is a no-op for BV
        pt_one = MakePlaintext({1});
    }

    Plaintext Decrypt(RLWE ct, size_t len = 1) const {
        Plaintext dec;
        cc->Decrypt(keys.secretKey, ct, &dec);
        dec->SetLength(len);
        return dec;
    };

    Plaintext MakePlaintext(const std::vector<int64_t>& value) const {
        return (GetParam().packing == TestCase::COEF)  // packing is a test parameter
            ? cc->MakeCoefPackedPlaintext(value)
            : cc->MakePackedPlaintext(value);
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
    // TODO: test mixed product in place of internal product for hybrid gadget
    if (GetParam().isHybrid) GTEST_SKIP() << "Internal product not supported for hybrid gadget";

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

using params::MakeContext;
using params::Resolve;
using params::Scheme;

// clang-format off
// Standard gadget
SETUP_TEST_SUITE(BV,
    TestCase{"standard", [] { return MakeContext(Resolve()); }},
    TestCase{"simd", [] { return MakeContext(Resolve()); }, TestCase::SIMD}
);

// Hybrid gadget
SETUP_TEST_SUITE(Hybrid,
    TestCase{"standard", [] { return MakeContext(Resolve(), Scheme::Hybrid); }, TestCase::Packing::COEF, true},
    TestCase{"simd", [] { return MakeContext(Resolve(), Scheme::Hybrid); }, TestCase::Packing::SIMD, true}
);
// clang-format on

}  // namespace spar::test