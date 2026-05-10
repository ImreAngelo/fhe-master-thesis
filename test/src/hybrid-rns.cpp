#include "core/gadget-bv.h"

using namespace lbcrypto;
using namespace bvrns;

DCRTPoly EvalInnerProduct(
    const std::vector<DCRTPoly>& D, 
    const std::vector<DCRTPoly>& P
) {
    // TODO: Ensure we are in EVALUATION format
    if (D.size() != P.size() || D.size() == 0) {
        throw std::runtime_error("Vector dimensions must match and be non-zero");
    }

    DCRTPoly result = D[0] * P[0];

    for (size_t i = 1; i < D.size(); i++) {
        result += (D[i] * P[i]);
    }

    return result;
}

TEST(HYBRID, main) {
    const std::vector<int64_t> value{-2};

    const auto params = params::Small<CryptoContextBGVRNS>();
    const auto cc = GenCryptoContext(params);
    
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    
    const auto keys = cc->KeyGen();
    
    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();
    
    // TODO: Move to context
    const auto ccRNS = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    
    /* NTT Format */ 
    {
        const auto mg = UnsignedDigitDecompose(ccRNS, m);
        const auto mp = PowerOfBase(ccRNS, m);
        const auto mm = EvalInnerProduct(mg, mp);
        ASSERT_EQ(mm, m * m);
    }

    /* Coefficient */
    {
        const auto mg = SignedDigitDecompose(ccRNS, m);
        const auto mp = PowerOfBase(ccRNS, m);
        const auto mm = EvalInnerProduct(mg, mp);
        ASSERT_EQ(mm, m * m);
    }
}

TEST(RGSW, ExternalProduct) {
    const std::vector<int64_t> value{3};

    const auto params = params::Small<CryptoContextBGVRNS>();
    const auto cc = GenCryptoContext(params);
    
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    
    const auto keys = cc->KeyGen();
    
    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();
    
    /* External Product */
    {
        const auto mult = cc->MakeCoefPackedPlaintext({2});
        const auto rlwe = cc->Encrypt(keys.publicKey, mult);
        
        const auto rgsw = Encrypt(cc, keys.publicKey, pt);
        const auto rExt = EvalExternalProduct(cc, rlwe, rgsw);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, rExt, &decrypted);
        decrypted->SetLength(value.size());
        
        DEBUG_PRINT("External Product: " << decrypted);

        const auto expected = cc->MakeCoefPackedPlaintext({2*value[0]});
        ASSERT_EQ(decrypted, expected);
    }

    /* Internal Product */
    {
        const auto mult = cc->MakeCoefPackedPlaintext({2});
        const auto a = Encrypt(cc, keys.publicKey, pt);
        const auto b = Encrypt(cc, keys.publicKey, mult);
        const auto rInt = EvalInternalProduct(cc, a, b);

        const auto one = cc->Encrypt(keys.publicKey, cc->MakeCoefPackedPlaintext({1}));
        const auto res = EvalExternalProduct(cc, one, rInt);

        Plaintext decrypted;
        Decrypt(cc, keys.secretKey, rInt, &decrypted);
        decrypted->SetLength(value.size());

        DEBUG_PRINT("Internal Product: " << decrypted);

        const auto expected = cc->MakeCoefPackedPlaintext({2*value[0]});
        ASSERT_EQ(decrypted, expected);
    }
}