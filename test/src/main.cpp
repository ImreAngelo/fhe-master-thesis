#include "server/homplacing.h"
#include "core/helpers.h"

#include "../cli_params.h"

#include <random>

using namespace lbcrypto;

/**
 * @brief Test MultiHomPlacing (sPAR alg 2) with N users.
 */
inline void TestServerWrite(uint32_t N, uint32_t candidates = 3, uint32_t bins = 3) {
    const auto bits = Log2(N);
    ASSERT_EQ(uint32_t(1) << bits, N); // ensure N is power of 2

    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(test_cli::g_mult_depth.value_or(8));
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
    // params.SetRingDim(test_cli::g_ring_dim.value_or(16384));
    params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDAUTO));
    params.SetGadgetDecomposition(test_cli::g_gadget_decomposition.value_or(39));
    params.SetGadgetBase(test_cli::g_gadget_base.value_or(10));

    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto ptZero = cc->MakePackedPlaintext({0});
    auto ptOne  = cc->MakePackedPlaintext({1});

    std::vector<std::vector<Ciphertext<DCRTPoly>>>     L_matrix(N, std::vector<Ciphertext<DCRTPoly>>(bins));
    std::vector<std::vector<RGSWCiphertext<DCRTPoly>>> I_matrix(N, std::vector<RGSWCiphertext<DCRTPoly>>(bins));
    for (uint32_t i = 0; i < N; i++) {
        for (uint32_t k = 0; k < bins; k++) {
            L_matrix[i][k] = cc->Encrypt(keyPair.publicKey, ptZero);
            I_matrix[i][k] = cc->EncryptRGSW(keyPair.publicKey, { 1 });
        }
    }

    // // Sanity: decrypt the bottom row of a fresh RGSW(1)
    // {
    //     auto r1 = cc->EncryptRGSW(keyPair.publicKey, { 1 });
    //     const size_t ell_sanity = r1.size() / 2;
    //     Plaintext p;
    //     cc->Decrypt(keyPair.secretKey, r1[ell_sanity], &p);
    //     p->SetLength(1);
    //     std::cout << "sanity RGSW(1)[ell] = " << p->GetPackedValue()[0] << std::endl;

    //     auto r2 = cc->EncryptRGSW(keyPair.publicKey, { 1 });
    //     auto r3 = cc->EvalInternalProduct(r1, r2);
    //     Plaintext p3;
    //     cc->Decrypt(keyPair.secretKey, r3[ell_sanity], &p3);
    //     p3->SetLength(1);
    //     std::cout << "sanity Int(RGSW(1), RGSW(1))[ell] = " << p3->GetPackedValue()[0] << std::endl;

    //     auto r4 = cc->EvalInternalProduct(r3, r2);
    //     Plaintext p4;
    //     cc->Decrypt(keyPair.secretKey, r4[ell_sanity], &p4);
    //     p4->SetLength(1);
    //     std::cout << "sanity Int(r3, RGSW(1))[ell] = " << p4->GetPackedValue()[0] << std::endl;

    //     // Sub(RGSW(1), RGSW(1)) should be RGSW(0).
    //     auto rZero = cc->EncryptRGSW(keyPair.publicKey, { 0 });
    //     RGSWCiphertext<DCRTPoly> rSub(r1.size());
    //     for (size_t i = 0; i < r1.size(); i++) rSub[i] = cc->EvalSub(r1[i], r2[i]);
    //     Plaintext pSub;
    //     cc->Decrypt(keyPair.secretKey, rSub[ell_sanity], &pSub);
    //     pSub->SetLength(1);
    //     std::cout << "sanity Sub(RGSW(1),RGSW(1))[ell] = " << pSub->GetPackedValue()[0] << std::endl;

    //     // Int(RGSW(1), Sub(RGSW(1),RGSW(1))) should be RGSW(0).
    //     auto rIntSub = cc->EvalInternalProduct(r1, rSub);
    //     Plaintext pIntSub;
    //     cc->Decrypt(keyPair.secretKey, rIntSub[ell_sanity], &pIntSub);
    //     pIntSub->SetLength(1);
    //     std::cout << "sanity Int(RGSW(1),Sub) [ell] = " << pIntSub->GetPackedValue()[0] << std::endl;

    //     // Mimic the algorithm: rOne, zero accumulator, add h
    //     auto rOne  = cc->EncryptRGSW(keyPair.publicKey, { 1 });
    //     auto hw    = rZero;                                           // start RGSW(0)
    //     // iter1: h = Int(RGSW(1), Sub(rOne, hw))  (should be RGSW(1))
    //     RGSWCiphertext<DCRTPoly> oneMinusHW1(rOne.size());
    //     for (size_t i = 0; i < rOne.size(); i++) oneMinusHW1[i] = cc->EvalSub(rOne[i], hw[i]);
    //     auto h1 = cc->EvalInternalProduct(r1, oneMinusHW1);
    //     // hw = Add(hw, h1)  (should be RGSW(1))
    //     RGSWCiphertext<DCRTPoly> hw1(rOne.size());
    //     for (size_t i = 0; i < rOne.size(); i++) hw1[i] = cc->EvalAdd(hw[i], h1[i]);
    //     Plaintext pHw1;
    //     cc->Decrypt(keyPair.secretKey, hw1[ell_sanity], &pHw1);
    //     pHw1->SetLength(1);
    //     std::cout << "sanity hw after 1 iter = " << pHw1->GetPackedValue()[0] << std::endl;

    //     // iter2: h2 = Int(RGSW(0), Sub(rOne, hw1))  (should be RGSW(0))
    //     RGSWCiphertext<DCRTPoly> oneMinusHW2(rOne.size());
    //     for (size_t i = 0; i < rOne.size(); i++) oneMinusHW2[i] = cc->EvalSub(rOne[i], hw1[i]);
    //     auto h2 = cc->EvalInternalProduct(rZero, oneMinusHW2);
    //     // hw2 = Add(hw1, h2)  (should be RGSW(1))
    //     RGSWCiphertext<DCRTPoly> hw2(rOne.size());
    //     for (size_t i = 0; i < rOne.size(); i++) hw2[i] = cc->EvalAdd(hw1[i], h2[i]);
    //     Plaintext pHw2;
    //     cc->Decrypt(keyPair.secretKey, hw2[ell_sanity], &pHw2);
    //     pHw2->SetLength(1);
    //     std::cout << "sanity hw after 2 iter = " << pHw2->GetPackedValue()[0] << std::endl;
    // }

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

        // hasWritten is RGSW; decrypt the bottom row (encrypts m·B^0 = m)
        const size_t ell = hasWritten.size() / 2;
        Plaintext hw;
        cc->Decrypt(keyPair.secretKey, hasWritten[ell], &hw);
        const auto& hwDecrypted = hw->GetPackedValue();
        std::cout << "user " << user << " hasWritten = " << hwDecrypted[0] << std::endl;

        ASSERT_EQ(hwDecrypted[0], 1);

        // std::cout << "L = " << ell << std::endl;

        for(const auto & r : hasWritten) {
            Plaintext row;
            cc->Decrypt(keyPair.secretKey, r, &row);
            row->SetLength(1);
            std::cout << row << std::endl;
        }

        // return;
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

// TEST(ServerWrite, N2_1_1) { TestServerWrite(2, 1, 1); }
TEST(ServerWrite, N2) { TestServerWrite(2); }

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
