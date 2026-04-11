#include "testing/Timer.h"
#include "server/HomPlacing.h"
#include "openfhe.h"

#include <gtest/gtest.h>

using namespace lbcrypto;


void TestExpandRLWE() 
{
    // using testing::Timer;
    // using Ciphertext = Ciphertext<DCRTPoly>;

    // constexpr uint32_t depth  = 2;
    // // constexpr int64_t  target = 2;   // target slot (binary: 10)

    // // Set up BGV-rns
    // CCParams<CryptoContextBGVRNS> params;
    // params.SetMultiplicativeDepth(depth);
    // params.SetPlaintextModulus(65537);

    // CryptoContext<DCRTPoly> cc;
    // KeyPair<DCRTPoly>       keys;
    
    // {
    //     Timer t("Setup");
    //     cc = GenCryptoContext(params);
    //     cc->Enable(PKE);
    //     cc->Enable(LEVELEDSHE);
        
    //     keys = cc->KeyGen();
    //     cc->EvalMultKeyGen(keys.secretKey);
    // }    

    // std::cout << "Setup complete" << std::endl; 

    // // Generate automorphism keys (client-side, needs secret key)
    // // uint32_t n = cc->GetRingDimension();
    // // std::cout << "Ring dimenson: " << n << std::endl;

    // // uint32_t n = 6;

    // auto indices = Server::ExpandRLWEAutoIndices(cc->GetRingDimension(), depth);

    // std::cout << "Indices: ";
    // for(auto i : indices) {
    //     std::cout << i << " ";
    // }
    // std::cout << std::endl;

    // // auto autoKeys = cc->EvalAutomorphismKeyGen(keys.secretKey, indices);

    // std::vector<uint32_t> indexList = {1, 2};
    // auto autoKeys = cc->EvalAutomorphismKeyGen(keys.secretKey, indexList);

    // std::cout << "Generated automorphism keys" << std::endl; 

    // // Encrypt the L index bits (binary encoding of target, MSB first)
    // Plaintext packedPt = cc->MakePackedPlaintext({ 1, 0 });
    // Ciphertext packedCt = cc->Encrypt(keys.secretKey, packedPt); 
    
    // std::cout << "Encrypted message" << std::endl; 

    // /// ---- SERVERSIDE -----

    // // Expand (server-side, no secret key needed)
    // auto expanded = Server::ExpandRLWE(cc, packedCt, depth, *autoKeys);
    
    // std::cout << "Expanded to RGSW" << std::endl; 
}



void TestAlgorithm2()
{
    using testing::Timer;
    using CT  = Ciphertext<DCRTPoly>;
    using CTVec = std::vector<CT>;

    constexpr uint32_t L     = 1;
    constexpr uint32_t eta   = 1u << L;   // 2
    constexpr uint32_t D     = 3;
    constexpr uint32_t K     = 3;
    constexpr uint32_t depth = 22;

    // Candidate bin indices (decimal), one per choice d.
    // Expected: first write lands at bin 1, slot 0.
    constexpr int64_t addrs[D] = {1, 0, 1};

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
    auto ctValue = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({42}));

    std::vector<CTVec> A(D);
    for (uint32_t d = 0; d < D; d++)
    {
        A[d].resize(L);
        for (uint32_t k = 0; k < L; k++)
        {
            int64_t bit = (addrs[d] >> (L - 1 - k)) & 1;
            A[d][k] = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({bit}));
        }

        std::cout << "A[" << d << "] = bin " << addrs[d] << " (bits:";
        for (uint32_t k = 0; k < L; k++)
            std::cout << " " << ((addrs[d] >> (L - 1 - k)) & 1);
        std::cout << ")\n";
    }

    // Initialise server state matrices (n × K)
    auto enc = [&](int64_t v) {
        return cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({v}));
    };

    std::vector<CTVec> dataMatrix(eta, CTVec(K));
    std::vector<CTVec> availMatrix(eta, CTVec(K));
    for (uint32_t i = 0; i < eta; i++)
        for (uint32_t k = 0; k < K; k++) {
            dataMatrix[i][k]  = enc(0);
            availMatrix[i][k] = enc(1);
        }

    // Run Algorithm 2
    std::cout << "\n=== Test: Algorithm 2 (HomPlacingStarNoExt) ===\n";
    CT hasWritten;
    {
        Timer t("HomPlacingStarNoExt");
        hasWritten = Server::HomPlacingStarNoExt(cc, ctValue, A, dataMatrix, availMatrix);
    }

    auto decrypt1 = [&](const CT& ct) -> int64_t {
        Plaintext pt;
        cc->Decrypt(keys.secretKey, ct, &pt);
        pt->SetLength(1);
        return pt->GetPackedValue()[0];
    };

    // hasWritten should be 1
    std::cout << "\nhasWritten = " << decrypt1(hasWritten) << " (expected 1)\n";

    // Data matrix
    std::cout << "\nData matrix L[i][k]:\n";
    for (uint32_t i = 0; i < eta; i++)
        for (uint32_t k = 0; k < K; k++) {
            int64_t got      = decrypt1(dataMatrix[i][k]);
            int64_t expected = (i == 1 && k == 0) ? 42 : 0;
            std::cout << "  L[" << i << "][" << k << "] = " << got
                      << " (expected " << expected << ")"
                      << (got == expected ? "" : "  MISMATCH") << "\n";
        }

    // Availability matrix
    std::cout << "\nAvailability matrix I[i][k]:\n";
    for (uint32_t i = 0; i < eta; i++)
        for (uint32_t k = 0; k < K; k++) {
            int64_t got      = decrypt1(availMatrix[i][k]);
            int64_t expected = (i == 1 && k == 0) ? 0 : 1;
            std::cout << "  I[" << i << "][" << k << "] = " << got
                      << " (expected " << expected << ")"
                      << (got == expected ? "" : "  MISMATCH") << "\n";
        }
}


void TestAlgorithm1()
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
}

TEST(Algorithm, HomPlacingNoExt)     { TestAlgorithm1(); }
TEST(Algorithm, HomPlacingStarNoExt) { TestAlgorithm2(); }