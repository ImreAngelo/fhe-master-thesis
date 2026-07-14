#include "server/write.h"
#include "core/context.h"
#include "core/utils/noise.h"
#include "core/utils/record.h"
#include "server/state.h"
#include <string>

namespace spar::test {

using namespace lbcrypto;

class Server : public ::testing::TestWithParam<uint32_t> {
   protected:
    static constexpr uint32_t K = 3;
    static constexpr uint32_t D = 3;

    uint32_t N = 0;

    ExtendedContext cc;
    KeyPair<DCRTPoly> keys;

    Plaintext zero_pt;
    Plaintext one_pt;

    server::Matrix<K> L_mat;
    server::Matrix<K> I_mat;

    void SetUp() override {
        N = GetParam();

        // WARN: Hybrid does not support internal product atm
        // cc = GenContextHybrid(params::Make(params::Set::Standard));
        cc = GenContextBV(params::Make(params::Set::Standard), 2);
        cc->Enable(PKE);

        keys = cc->KeyGen();

        zero_pt = cc->MakeCoefPackedPlaintext({0});
        one_pt = cc->MakeCoefPackedPlaintext({1});

        std::tie(I_mat, L_mat) = spar::server::InitializeStateMatrices<K>(cc, keys.publicKey, N);
    }

    std::vector<std::vector<RGSW>> MakeZ(uint32_t target) {
        std::vector<RGSW> hot(N);
        for (uint32_t i = 0; i < N; i++) {
            hot[i] = cc->EncryptRGSW(keys.publicKey, (i == target) ? one_pt : zero_pt);
        }
        return std::vector<std::vector<RGSW>>(D, hot);
    }
};

TEST_P(Server, Write) {
    const auto one = cc->Encrypt(keys.publicKey, one_pt); // TODO: Write should output hasNotWritten as an RLWE
    const auto expected = cc->MakeCoefPackedPlaintext({0});

    RECORD_START("results/write-N" + std::to_string(N) + ".csv", "n,msb,noise");
    for (uint32_t r = 0; r < N; r++) {
        const auto Vr = cc->MakeCoefPackedPlaintext({static_cast<int64_t>(r + 1)});
        const auto z = MakeZ(r);

        const auto nothw = server::Write<K, D>(cc, keys.publicKey, Vr, N, L_mat, I_mat, z, keys.secretKey);
        const auto result = cc->EvalExternalProduct(one, nothw);

        PRINT_MAX_NOISE_MSB(cc, result, keys.secretKey);
        RECORD_MAX_NOISE(r, cc, result, keys.secretKey);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, result, &decrypted);
        decrypted->SetLength(1);

        // Verify user has written
        ASSERT_EQ(decrypted, expected) << "User " << r;
    }
    RECORD_END();

    auto decrypt = [&](const RGSW& ct) {
        Plaintext pt;
        cc->Decrypt(keys.secretKey, cc->EvalExternalProduct(one, ct), &pt);
        pt->SetLength(1);
        return pt;
    };

    // Verify final state
    for (uint32_t i = 0; i < N; i++) {
        for (uint32_t k = 0; k < K; k++) {
            const auto expected_L = cc->MakeCoefPackedPlaintext({(k == 0) ? static_cast<int64_t>(i + 1) : 0});
            const auto expected_I = cc->MakeCoefPackedPlaintext({(k == 0) ? 0 : 1});

            EXPECT_EQ(decrypt(L_mat[i][k]), expected_L) << "L[" << i << "][" << k << "]";
            EXPECT_EQ(decrypt(I_mat[i][k]), expected_I) << "I[" << i << "][" << k << "]";
        }
    }
}

INSTANTIATE_TEST_SUITE_P(Sizes, Server, ::testing::Values(2u, 16u),
                         [](const auto& info) { return "N" + std::to_string(info.param); });

}  // namespace spar::test
