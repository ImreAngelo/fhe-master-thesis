#include "server/homplacing.h"
#include "core/helpers.h"
#define DEBUG_LOGGING

#include <random>

using namespace lbcrypto;

/**
 * @brief Test MultiHomPlacing (sPAR alg 2) with N users.
 */
inline void TestMultiHomPlacing(uint32_t N, uint32_t candidates = 3, uint32_t bins = 3) {
    const auto bits = Log2(N);
    ASSERT_EQ(uint32_t(1) << bits, N);

    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(14);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(32768);
    params.SetScalingTechnique(FIXEDAUTO);
    params.SetSecurityLevel(HEStd_NotSet);
    params.SetGadgetBase(30);
    params.SetGadgetDecomposition(22);

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto ptZero = cc->MakePackedPlaintext({0});
    auto ptOne  = cc->MakePackedPlaintext({1});

    std::vector<std::vector<Ciphertext<DCRTPoly>>> L_matrix(N, std::vector<Ciphertext<DCRTPoly>>(bins));
    std::vector<std::vector<Ciphertext<DCRTPoly>>> I_matrix(N, std::vector<Ciphertext<DCRTPoly>>(bins));
    for (uint32_t i = 0; i < N; i++) {
        for (uint32_t k = 0; k < bins; k++) {
            L_matrix[i][k] = cc->Encrypt(keyPair.publicKey, ptZero);
            I_matrix[i][k] = cc->Encrypt(keyPair.publicKey, ptOne);
        }
    }

    std::mt19937 rng(42);
    std::uniform_int_distribution<uint32_t> dist(0, N - 1);

    for (uint32_t user = 0; user < N; user++) {
        auto value = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({int64_t(user + 1)}));

        std::vector<std::vector<RGSWCiphertext<DCRTPoly>>> A(
            candidates, std::vector<RGSWCiphertext<DCRTPoly>>(bits));
        for (uint32_t d = 0; d < candidates; d++) {
            const uint32_t idx = dist(rng);
            for (uint32_t b = 0; b < bits; b++) {
                const int64_t bit = (idx >> (bits - 1 - b)) & 1;
                A[d][b] = cc->EncryptRGSW(keyPair.publicKey, { bit });
            }
        }

        auto hasWritten = Server::MultiHomPlacing(cc, keyPair.publicKey, value, A, L_matrix, I_matrix);

        Plaintext hw;
        cc->Decrypt(keyPair.secretKey, hasWritten, &hw);
        std::cout << "user " << user << " hasWritten=" << hw->GetPackedValue()[0] << std::endl;
    }

    std::cout << "L_matrix:" << std::endl;
    for (uint32_t i = 0; i < N; i++) {
        for (uint32_t k = 0; k < bins; k++) {
            Plaintext pt;
            cc->Decrypt(keyPair.secretKey, L_matrix[i][k], &pt);
            std::cout << pt->GetPackedValue()[0] << " ";
        }
        std::cout << std::endl;
    }
}

TEST(MultiHomPlacing, N1) { TestMultiHomPlacing(1); }
TEST(MultiHomPlacing, N2) { TestMultiHomPlacing(2); }
