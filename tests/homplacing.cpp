#include "server/HomPlacing.h"


void TestAlgorithm1(const uint32_t depth = 2, const int64_t target = 2)
{
    using namespace lbcrypto;

    // Set up BGV-rns
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(depth);
    params.SetPlaintextModulus(65537);

    CryptoContext<DCRTPoly> cc;
    cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    
    KeyPair<DCRTPoly> keys;
    keys = cc->KeyGen();

    cc->EvalMultKeyGen(keys.secretKey);

    // Encrypt the value to be placed
    constexpr auto val = 8;
    Plaintext Vr = cc->MakePackedPlaintext({ val });
    auto ctValue = cc->Encrypt(keys.publicKey, Vr);

    // Encrypt the L index bits (binary encoding of target, MSB first)
    std::vector<Ciphertext<DCRTPoly>> ctBits;
    ctBits.reserve(depth);
    
    for (uint32_t k = 0; k < depth; k++) {
        int64_t bit = (target >> (depth - 1 - k)) & 1;
        ctBits.push_back(cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({bit})));
    }

    auto res = Server::HomPlacingNoExt(cc, ctValue, ctBits);
    
    // TEST: Confirm val is placed in correct slot
    const auto target_idx = static_cast<uint32_t>(target);
    const auto slots = (uint32_t(1) << depth);

    ASSERT_EQ(slots, static_cast<uint32_t>(res.size())) << "Incorrect number of slots/levels";
    
    for (uint32_t i = 0; i < slots; i++) {
        Plaintext pi;
        cc->Decrypt(keys.secretKey, res[i], &pi);
        pi->SetLength(1);
        
        SCOPED_TRACE("Slot " + std::to_string(i));
        if (i == target_idx) {
            ASSERT_EQ(val, pi->GetPackedValue()[0]);
        } else {
            ASSERT_EQ(0, pi->GetPackedValue()[0]);
        }
    }
}

TEST(Algorithm, HomPlacingNotPackedNoExt) { TestAlgorithm1(2, 2); }
// TEST(Algorithm, HomPlacingStarNoExt) { TestAlgorithm2(); }

// void TestAlgorithm2()
// {
//     using testing::Timer;
//     using CT  = Ciphertext<DCRTPoly>;
//     using CTVec = std::vector<CT>;

//     constexpr uint32_t L     = 1;
//     constexpr uint32_t eta   = 1u << L;   // 2
//     constexpr uint32_t D     = 3;
//     constexpr uint32_t K     = 3;
//     constexpr uint32_t depth = 22;

//     // Candidate bin indices (decimal), one per choice d.
//     // Expected: first write lands at bin 1, slot 0.
//     constexpr int64_t addrs[D] = {1, 0, 1};

//     CCParams<CryptoContextBGVRNS> params;
//     params.SetMultiplicativeDepth(depth);
//     params.SetPlaintextModulus(65537);

//     CryptoContext<DCRTPoly> cc;
//     KeyPair<DCRTPoly>       keys;

//     {
//         Timer t("Setup");
//         cc = GenCryptoContext(params);
//         cc->Enable(PKE);
//         cc->Enable(LEVELEDSHE);
//         keys = cc->KeyGen();
//         cc->EvalMultKeyGen(keys.secretKey);
//     }

//     // Encrypt the value to be placed
//     auto ctValue = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({42}));

//     std::vector<CTVec> A(D);
//     for (uint32_t d = 0; d < D; d++)
//     {
//         A[d].resize(L);
//         for (uint32_t k = 0; k < L; k++)
//         {
//             int64_t bit = (addrs[d] >> (L - 1 - k)) & 1;
//             A[d][k] = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({bit}));
//         }

//         std::cout << "A[" << d << "] = bin " << addrs[d] << " (bits:";
//         for (uint32_t k = 0; k < L; k++)
//             std::cout << " " << ((addrs[d] >> (L - 1 - k)) & 1);
//         std::cout << ")\n";
//     }

//     // Initialise server state matrices (n × K)
//     auto enc = [&](int64_t v) {
//         return cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({v}));
//     };

//     std::vector<CTVec> dataMatrix(eta, CTVec(K));
//     std::vector<CTVec> availMatrix(eta, CTVec(K));
//     for (uint32_t i = 0; i < eta; i++)
//         for (uint32_t k = 0; k < K; k++) {
//             dataMatrix[i][k]  = enc(0);
//             availMatrix[i][k] = enc(1);
//         }

//     // Run Algorithm 2
//     std::cout << "\n=== Test: Algorithm 2 (HomPlacingStarNoExt) ===\n";
//     CT hasWritten;
//     {
//         Timer t("HomPlacingStarNoExt");
//         hasWritten = Server::HomPlacingStarNoExt(cc, ctValue, A, dataMatrix, availMatrix);
//     }

//     auto decrypt1 = [&](const CT& ct) -> int64_t {
//         Plaintext pt;
//         cc->Decrypt(keys.secretKey, ct, &pt);
//         pt->SetLength(1);
//         return pt->GetPackedValue()[0];
//     };

//     // hasWritten should be 1
//     std::cout << "\nhasWritten = " << decrypt1(hasWritten) << " (expected 1)\n";

//     // Data matrix
//     std::cout << "\nData matrix L[i][k]:\n";
//     for (uint32_t i = 0; i < eta; i++)
//         for (uint32_t k = 0; k < K; k++) {
//             int64_t got      = decrypt1(dataMatrix[i][k]);
//             int64_t expected = (i == 1 && k == 0) ? 42 : 0;
//             std::cout << "  L[" << i << "][" << k << "] = " << got
//                       << " (expected " << expected << ")"
//                       << (got == expected ? "" : "  MISMATCH") << "\n";
//         }

//     // Availability matrix
//     std::cout << "\nAvailability matrix I[i][k]:\n";
//     for (uint32_t i = 0; i < eta; i++)
//         for (uint32_t k = 0; k < K; k++) {
//             int64_t got      = decrypt1(availMatrix[i][k]);
//             int64_t expected = (i == 1 && k == 0) ? 0 : 1;
//             std::cout << "  I[" << i << "][" << k << "] = " << got
//                       << " (expected " << expected << ")"
//                       << (got == expected ? "" : "  MISMATCH") << "\n";
//         }
// }