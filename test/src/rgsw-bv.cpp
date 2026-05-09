#define TEST_INTERNAL_FUNCTIONS
#define CENTER(integer, modulus) (((integer) > (modulus) / 2) ? ((integer % (2*modulus)) - (modulus)) : (integer))

#include "core/context.h"
#include "core/helpers.h"
#include "core/params.h"
#include "core/rgsw.h"

#include "encoding/plaintextfactory.h"

#include "../cli_params.h"

#include <cstdint>
#include <cmath>
#include <iostream>


using namespace lbcrypto;


/**
 * @brief Wrap a noise-free encoded ring element back into a packed Plaintext.
 *
 * Assumes `element` already represents an encoded plaintext (no scaling, no
 * key-switching residue) — e.g. the output of the BV-RNS gadget identity.
 * PackedEncoding::Decode() reads tower 0, applies Unpack, and reduces mod t.
 */
inline Plaintext DCRTToPackedPlaintext(const CryptoContext<DCRTPoly>& cc, DCRTPoly element) {
    // PackedEncoding::Unpack expects COEFFICIENT-form input
    element.SetFormat(Format::COEFFICIENT);
    auto pt = PlaintextFactory::MakePlaintext(
        PACKED_ENCODING,
        cc->GetElementParams(),
        cc->GetEncodingParams(),
        cc->getSchemeId());
    pt->GetElement<DCRTPoly>() = std::move(element);
    pt->Decode();
    return pt;
}

/**
 * @brief Used to verify the gadget propterty
 */
inline DCRTPoly InnerProduct(const std::vector<DCRTPoly>& u, const std::vector<DCRTPoly>& v) {
    if (u.empty() || u.size() != v.size())
        throw std::runtime_error("Vector sizes are invalid or do not match.");

    DCRTPoly result(u[0].GetParams(), u[0].GetFormat(), true);
    for (size_t i = 0; i < u.size(); i++)
        result += u[i] * v[i];
    return result;
}

/// @todo Move to cli_params.h or create abstraction to get common set of params
inline CCParams<CryptoContextBGVRNS> GetParams() {
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(test_cli::g_mult_depth.value_or(1));
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
    params.SetRingDim(test_cli::g_ring_dim.value_or(1 << 14));
    // params.SetNumLargeDigits(2);

    params.SetMaxRelinSkDeg(0); // Force no relinearization keys

    // RGSW rows are built by hand; avoid per-level scaling (S_L = 1 needed).
    params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDMANUAL));

    DEBUG_PRINT("Depth = " << params.GetMultiplicativeDepth());
    DEBUG_PRINT("Ring Dim. = " << params.GetRingDim());
    DEBUG_PRINT("Plaintext mod = " << params.GetPlaintextModulus());

    return params;
}

/**
 * @brief Verify the BV-RNS gadget identities for an arbitrary plaintext element.
 *
 *   1. <D_Q(m), g>      ≡ m   (mod Q)   — reconstruction
 *   2. <D_Q(m), P_Q(m)> ≡ m·m (mod Q)   — multiplicative pairing
 */
inline void RunTest(const std::vector<int64_t>& value) {
    const CCParams<CryptoContextBGVRNS> params = GetParams();
    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();

    Plaintext pt = cc->MakePackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();
    m.SetFormat(Format::EVALUATION);

    const auto d = cc->Decompose(m);

    // Identity 1: reconstruction
    const auto g = cc->GadgetVector();
    DCRTPoly reconstructed = InnerProduct(d, g);
    ASSERT_EQ(reconstructed, m);

    // Round-trip back to a Plaintext via the high-level API.
    Plaintext recovered = DCRTToPackedPlaintext(cc, reconstructed);
    recovered->SetLength(value.size());
    ASSERT_EQ(recovered->GetPackedValue(), value);

    // Identity 2: <D(m), P(m)> = m·m
    const auto P = cc->GadgetMul(m);
    DCRTPoly mm = m * m;
    ASSERT_EQ(InnerProduct(d, P), mm);

    // RGSW
    const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt);

    // External product:  RGSW(value) ⊡ RLWE(ones)  →  RLWE(value)  (slot-wise mul).
    const std::vector<int64_t> ones(value.size(), 1);
    const auto rlwe_ones = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(ones));
    const auto res = cc->EvalExternalProduct(rlwe_ones, rgsw);

    Plaintext decrypted;
    cc->Decrypt(keys.secretKey, res, &decrypted);
    decrypted->SetLength(value.size());

    DEBUG_PRINT(pt);
    DEBUG_PRINT(decrypted);

    ASSERT_EQ(decrypted->GetPackedValue(), value);
}

TEST(RGSW_BVRNS, b0)    { RunTest({ 0 }); }
TEST(RGSW_BVRNS, b1)    { RunTest({ 1 }); }
TEST(RGSW_BVRNS, multi) { RunTest({ 1, 2, 3, 4, 5, 6, 7, 8 }); }

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
