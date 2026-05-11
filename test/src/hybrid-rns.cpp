#define TEST_INTERNAL_FUNCTIONS
#include "core/include/context.h"

TEST(HYBRID, rgsw) {
    using namespace lbcrypto;

    const std::vector<int64_t> value{3};

    const auto ps = params::Small<CryptoContextBGVRNS>();
    const auto cc = Context::GenExtendedCryptoContext(ps);
    
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    
    const auto keys = cc->KeyGen();
    
    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);

    // Gadget Property
    {
        const DCRTPoly m = pt->GetElement<DCRTPoly>();

        const DCRTPoly pm = cc->Power(m);
        const DCRTPoly dm = cc->Decompose(m);

        const DCRTPoly mult = pm * dm;

        const auto mm = cc->ApproxModDown(mult);
        ASSERT_EQ(mm, m * m);
    }

    // External Product
    {
        DEBUG_PRINT("\n[EXTERNAL PRODUCT]");

        const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt);
        const auto rlwe = cc->Encrypt(keys.publicKey, pt);
        const auto ext = cc->EvalExternalProduct(rlwe, rgsw);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, ext, &decrypted);
        decrypted->SetLength(value.size());

        DEBUG_PRINT("External Product: " << decrypted);

        const auto expected = cc->MakeCoefPackedPlaintext({value[0] * value[0]});
        ASSERT_EQ(decrypted, expected);
    }

    // Internal Product
    {
        DEBUG_PRINT("\n[INTERNAL PRODUCT]");

        const auto rgsw = cc->EncryptRGSW(keys.publicKey, pt);
        const auto prod = cc->EvalInternalProduct(rgsw, rgsw);
        
        // TODO: Create decryption helper for RGSW
        const auto rlwe = cc->Encrypt(keys.publicKey, cc->MakeCoefPackedPlaintext({1}));
        const auto dec = cc->EvalExternalProduct(rlwe, prod);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, dec, &decrypted);
        decrypted->SetLength(value.size());

        DEBUG_PRINT("Internal Product: " << decrypted);

        const auto expected = cc->MakeCoefPackedPlaintext({value[0] * value[0]});
        ASSERT_EQ(decrypted, expected);
    }
}