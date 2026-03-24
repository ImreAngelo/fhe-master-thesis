#include "testing/Timer.h"
#include "server/HomPlacing.h"
#include "openfhe.h"

using namespace lbcrypto;

int main() 
{
    using testing::Timer;

    constexpr uint32_t depth  = 2;
    constexpr int64_t  target = 2;   // target slot (binary: 10)

    // Set up BGV-rns
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(depth);
    params.SetPlaintextModulus(65537);

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly>       keys;

    {
        Timer t("Setup");
        cc = GenCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);
        
        keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
    }

    // Encrypt the value to be placed
    Plaintext Vr = cc->MakePackedPlaintext({8});
    auto ctValue = cc->Encrypt(keys.publicKey, Vr);

    // Encrypt the L index bits (binary encoding of target, MSB first)
    std::vector<Ciphertext<DCRTPoly>> ctBits;
    ctBits.reserve(depth);
    
    std::cout << "Encrypted bits: ";
    for (uint32_t k = 0; k < depth; k++)
    {
        int64_t bit = (target >> (depth - 1 - k)) & 1;
        ctBits.push_back(cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({bit})));
        std::cout << bit << " ";
    }
    std::cout << std::endl;

    // Test
    std::cout << "\n=== Test 1: Algorithm 1 without external product ===\n";
    {
        Timer t("Total Test 1");
        auto res = Server::HomPlacingNoExt(cc, ctValue, ctBits);

        std::cout << "Result: ";
        for (const auto& xi : res)
        {
            lbcrypto::Plaintext pi;
            cc->Decrypt(keys.secretKey, xi, &pi);
            pi->SetLength(1);
            std::cout << pi->GetPackedValue()[0] << " ";
        }
        std::cout << "\n";
    }

    return 0;
}