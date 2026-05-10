#include "core/gadget-bv.h"

using namespace lbcrypto;
using namespace bvrns;

TEST(DECOMPOSE_B, main) {
    const std::vector<int64_t> value{-2};

    const auto params = params::Small<CryptoContextBGVRNS>();
    const auto cc = GenCryptoContext(params);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const auto keys = cc->KeyGen();

    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();

    // Get gadget decomposition vector
    const auto ccRNS = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());

    /* NTT Format */ 
    {
        DEBUG_PRINT("");
        const auto mg = UnsignedDigitDecompose(ccRNS, m);
        const auto mp = PowerOfBase(ccRNS, m);
        for(const auto& l : mg) { DEBUG_PRINT(l); } DEBUG_PRINT("");
        for(const auto& l : mp) { DEBUG_PRINT(l); }
    }

    
    /* Coefficient */
    {
        DEBUG_PRINT("");
        const auto mg = SignedDigitDecompose(ccRNS, m);
        const auto mp = PowerOfBase(ccRNS, m);
        for(const auto& l : mg) { DEBUG_PRINT(l); } DEBUG_PRINT("");
        for(const auto& l : mp) { DEBUG_PRINT(l); }
    }
}