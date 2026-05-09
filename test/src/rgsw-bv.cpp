#define TEST_INTERNAL_FUNCTIONS

#include "core/context.h"

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

/**
 * @brief Verify the BV-RNS gadget identities for an arbitrary plaintext element.
 *
 *   1. <D_Q(m), g>      ≡ m   (mod Q)   — reconstruction
 *   2. <D_Q(m), P_Q(m)> ≡ m·m (mod Q)   — multiplicative pairing
 */
inline void RunTest(const std::vector<int64_t>& value) {
    const auto params = params::Create<CryptoContextBGVRNS>();

    const auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();

    Plaintext pt = cc->MakePackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();
    m.SetFormat(Format::EVALUATION);

    const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt);
    const auto d = cc->Decompose(m);

    Plaintext tmp;
    cc->Decrypt(keys.secretKey, rgsw, &tmp);
    tmp->SetLength(value.size());
    DEBUG_PRINT("Encrypted -> " << tmp);

    // Gadget Identity 1: reconstruction
    {
        const auto g = cc->GadgetVector();
        DCRTPoly reconstructed = InnerProduct(d, g);
        ASSERT_EQ(reconstructed, m);

        Plaintext recovered = DCRTToPackedPlaintext(cc, reconstructed);
        recovered->SetLength(value.size());
        ASSERT_EQ(recovered->GetPackedValue(), value);
    }

    // Gadget Identity 2: <D(m), P(m)> = m·m
    {
        const auto P = cc->GadgetMul(m);
        DCRTPoly mm = m * m;
        ASSERT_EQ(InnerProduct(d, P), mm);
    }

    // External product:  RGSW(value) x RLWE(1) = RLWE(value),  slot-wise for MakePackedPlaintext
    {
        const auto ones = cc->MakePackedPlaintext(std::vector<int64_t>(value.size(), 1));
        const auto rlwe = cc->Encrypt(keys.publicKey, ones);
        const auto res = cc->EvalExternalProduct(rlwe, rgsw);
    
        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, res, &decrypted);
        decrypted->SetLength(value.size());
    
        ASSERT_EQ(decrypted->GetPackedValue(), value);
        DEBUG_PRINT("External x 1 = " << decrypted);
    }

    // External product:  RGSW(value) x RLWE(n) = RLWE(n*value),  slot-wise for MakePackedPlaintext
    {
        constexpr int64_t scale = 2;

        const auto scalars = cc->MakePackedPlaintext(std::vector<int64_t>(value.size(), scale));
        const auto rlwe = cc->Encrypt(keys.publicKey, scalars);
        const auto res = cc->EvalExternalProduct(rlwe, rgsw);
    
        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, res, &decrypted);
        decrypted->SetLength(value.size());
    
        std::vector<int64_t> scaled(value.size());
        for (size_t i = 0; i < value.size(); ++i) {
            scaled[i] = value[i] * scale;
        }

        ASSERT_EQ(decrypted->GetPackedValue(), scaled);
        DEBUG_PRINT("External x " << scale << " = " << decrypted);
    }

    // Internal product: RGSW(a) x RGSW(b) = RGSW(a*b)
    {
        constexpr int64_t scale = 3;

        const auto scalar = cc->MakePackedPlaintext(std::vector<int64_t>(value.size(), scale));
        const auto identity = cc->EncryptRGSW(keys.publicKey, scalar);
        const auto res = cc->EvalInternalProduct(identity, rgsw);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, res, &decrypted);
        decrypted->SetLength(value.size());
        
        DEBUG_PRINT("Internal x " << scale << " = " << decrypted);
        
        const auto& slots = decrypted->GetPackedValue();
        for (size_t i = 0; i < value.size(); i++) {
            auto expected = scale * value[i];
            ASSERT_EQ(expected, slots[i]) << "slot " << i << std::endl;
        }

        // Internal product twice
        {
            const auto sqr = cc->EvalInternalProduct(res, res);

            Plaintext decrypted;
            cc->Decrypt(keys.secretKey, sqr, &decrypted);
            decrypted->SetLength(value.size());

            DEBUG_PRINT("Internal squared: " << decrypted);
        }
    }
}

TEST(RGSW_BVRNS, b0)    { RunTest({ 0 }); }
TEST(RGSW_BVRNS, b1)    { RunTest({ 1 }); }
TEST(RGSW_BVRNS, multi) { RunTest({ 1, 2, 3, 4, 5, 6, 7, 8 }); }

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
