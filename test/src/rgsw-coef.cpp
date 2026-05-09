#define TEST_INTERNAL_FUNCTIONS

#include "core/context.h"

#include <cstdint>
#include <vector>


using namespace lbcrypto;


/**
 * @brief Wrap a noise-free encoded ring element into a CoefPacked plaintext.
 *
 * Symmetric helper to DCRTToPackedPlaintext in rgsw-bv.cpp. Used to round-trip
 * the output of the gadget identity (which is a DCRTPoly) back to a
 * CoefPackedEncoding plaintext for slot-level inspection.
 */
inline Plaintext DCRTToCoefPackedPlaintext(const CryptoContext<DCRTPoly>& cc, DCRTPoly element) {
    element.SetFormat(Format::COEFFICIENT);
    auto pt = PlaintextFactory::MakePlaintext(
        COEF_PACKED_ENCODING,
        cc->GetElementParams(),
        cc->GetEncodingParams(),
        cc->getSchemeId());
    pt->GetElement<DCRTPoly>() = std::move(element);
    pt->Decode();
    return pt;
}

/// @brief Used to verify the gadget property
inline DCRTPoly InnerProduct(const std::vector<DCRTPoly>& u, const std::vector<DCRTPoly>& v) {
    if (u.empty() || u.size() != v.size())
        throw std::runtime_error("Vector sizes are invalid or do not match.");

    DCRTPoly result(u[0].GetParams(), u[0].GetFormat(), true);
    for (size_t i = 0; i < u.size(); i++)
        result += u[i] * v[i];
    return result;
}

/**
 * @brief Schoolbook polynomial multiplication mod (x^N + 1, t).
 *
 * Coefficients of the output are returned in the centered representative
 * (-t/2, t/2], to match how OpenFHE decodes a CoefPacked plaintext.
 */
inline std::vector<int64_t> PolyMulModXN(
    const std::vector<int64_t>& a,
    const std::vector<int64_t>& b,
    const size_t N,
    const int64_t t)
{
    std::vector<int64_t> r(N, 0);
    for (size_t i = 0; i < a.size(); i++)
        for (size_t j = 0; j < b.size(); j++) {
            const size_t k = i + j;
            if (k < N) r[k] += a[i] * b[j];
            else       r[k - N] -= a[i] * b[j];   // x^N = -1
        }
    for (size_t k = 0; k < N; k++) {
        int64_t v = ((r[k] % t) + t) % t;          // [0, t)
        if (v > t / 2) v -= t;                      // (-t/2, t/2]
        r[k] = v;
    }
    return r;
}

/**
 * @brief Verify the BV-RNS gadget identities and the external product for
 *        coefficient-packed plaintexts. Multiplication is the polynomial
 *        product mod (x^N + 1, t) — NOT slot-wise.
 *
 *   Gadget identities:
 *     1. <D_Q(m), g>      ≡ m   (mod Q)
 *     2. <D_Q(m), P_Q(m)> ≡ m·m (mod Q)
 *
 *   External product: RGSW(a) ⊡ RLWE(b) → RLWE(a·b mod (x^N+1, t)).
 */
inline void RunTest(const std::vector<int64_t>& value, const std::vector<int64_t>& multiplier) {
    CCParams<CryptoContextBGVRNS> params;
    params.SetRingDim(1 << 11);
    params.SetPlaintextModulus(128);
    params.SetMultiplicativeDepth(2);
    params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);
    
    const auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const auto keys = cc->KeyGen();

    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();
    m.SetFormat(Format::EVALUATION);

    const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt);
    
    const auto d    = cc->Decompose(m);

    const size_t N  = cc->GetRingDimension();
    const int64_t t = static_cast<int64_t>(params.GetPlaintextModulus());

    // Gadget Identity 1: reconstruction
    {
        const auto g = cc->GadgetVector();
        DCRTPoly reconstructed = InnerProduct(d, g);
        ASSERT_EQ(reconstructed, m);
    }

    // Gadget Identity 2: <D(m), P(m)> = m·m
    {
        const auto P = cc->GadgetMul(m);
        DCRTPoly mm = m * m;
        ASSERT_EQ(InnerProduct(d, P), mm);
    }

    // External product: RGSW(value) x RLWE(multiplier) = RLWE(value * multiplier mod (x^N+1, t))
    {
        const Plaintext mpt = cc->MakeCoefPackedPlaintext(multiplier);
        const auto rlwe     = cc->Encrypt(keys.publicKey, mpt);
        const auto res      = cc->EvalExternalProduct(rlwe, rgsw);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, res, &decrypted);
        // Don't truncate: polynomial product spans all N coefficients.

        const auto expected = PolyMulModXN(value, multiplier, N, t);
        ASSERT_EQ(decrypted->GetCoefPackedValue(), expected);
        DEBUG_PRINT("External coef-poly mul ok");
    }

    // Internal product: RGSW(a) ⊠ RGSW(b) = RGSW(a·b),
    // checked by an additional external product against RLWE(1) (i.e. polynomial 1).
    {
        const Plaintext mpt   = cc->MakeCoefPackedPlaintext(multiplier);
        const auto rgsw_b     = cc->EncryptRGSW(keys.publicKey, mpt);
        const auto rgsw_ab    = cc->EvalInternalProduct(rgsw_b, rgsw);

        const Plaintext one_pt = cc->MakeCoefPackedPlaintext({1});
        const auto rlwe_one    = cc->Encrypt(keys.publicKey, one_pt);
        const auto res         = cc->EvalExternalProduct(rlwe_one, rgsw_ab);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, res, &decrypted);

        const auto expected = PolyMulModXN(value, multiplier, N, t);
        ASSERT_EQ(decrypted->GetCoefPackedValue(), expected);
        DEBUG_PRINT("Internal coef-poly mul ok");
    }
}

// Constant multiplier (no wraparound, no convolution).
TEST(RGSW_BVRNS_Coef, by_one)        { RunTest({1, 2, 3, 4, 5}, {1}); }
TEST(RGSW_BVRNS_Coef, by_const)      { RunTest({1, 2, 3, 4, 5}, {3}); }

// Pure shift: multiplier = x^k. With k+deg(value) < N, no wraparound.
TEST(RGSW_BVRNS_Coef, shift_x)       { RunTest({1, 2, 3}, {0, 1}); }
TEST(RGSW_BVRNS_Coef, shift_x2)      { RunTest({1, 2, 3}, {0, 0, 1}); }

// Genuine polynomial multiplication.
TEST(RGSW_BVRNS_Coef, poly_mul)      { RunTest({1, 2, 3, 4}, {1, 1}); }
TEST(RGSW_BVRNS_Coef, square)        { RunTest({1, 2, 3}, {1, 2, 3}); }
TEST(RGSW_BVRNS_Coef, mixed_signs)   { RunTest({1, -2, 3, -4}, {-1, 2, -3}); }

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
