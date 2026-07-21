#include "constants-defs.h"
#include "core/context.h"
#include "core/types.h"
#include "core/utils/noise.h"
#include "core/utils/record.h"
#include "core/utils/timer.h"
#include "key/publickey-fwd.h"
#include "server/state.h"
#include "server/write.h"
#include <gtest/gtest.h>
#include <bitset>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace spar::test {

using namespace core;

/// @brief Container for each users private info
struct Client {
    uint32_t id;
    lbcrypto::KeyPair<Poly> kpShard;  // (joint pk after i's contribution, sk_i)
    std::vector<std::vector<RGSW>> indices;
    RLWE value;
    RGSW failed;
};

/// @brief Encrypts a one-hot indicator of length `len` with the 1 at position `idx`
std::vector<RGSW> OneHot(const ExtendedContext& cc, const PublicKey& pk, const uint32_t len, const uint32_t idx) {
    const auto zero_pt = cc->MakeCoefPackedPlaintext({0});
    const auto one_pt = cc->MakeCoefPackedPlaintext({1});

    // std::cout << idx << ", ";

    std::vector<RGSW> slots(len);
    for (uint32_t i = 0; i < len; i++) {
        slots[i] = cc->EncryptRGSW(pk, (i == idx) ? one_pt : zero_pt);
    }
    return slots;
}

/// @brief Client encryption matching bandwidth-optimized scenario from paper
template <typename T = uint32_t>
RLWE EncryptBinaryIndicies(const CryptoContext& cc, const PublicKey& pk, uint32_t l, T idx) {
    // static_assert(sizeof(T) >= length, "");
    // TODO: Assert idx can be represented by l bits

    std::bitset<sizeof(T)> bits;
    std::vector<int64_t> bits_vec(l);

    for (uint32_t i = 0; i < l; i++) {
        bits_vec[i] = bits[i];
    }

    const auto pt = cc->MakeCoefPackedPlaintext(bits_vec);
    return cc->Encrypt(pk, pt);
}

/// @brief Partial decryption by all clients
std::vector<std::vector<RLWE>> MPDecryptPartials(const CryptoContext& cc, const std::vector<RLWE>& cts, const uint32_t n,
                                                 const std::vector<PrivateKey>& sks) {
    std::vector<std::vector<RLWE>> partials(n);

    partials[0] = cc->MultipartyDecryptLead(cts, sks[0]);
    for (uint32_t i = 1; i < n; i++) {
        partials[i] = cc->MultipartyDecryptMain(cts, sks[i]);
    }

    return partials;
}

/// @brief Final decryption by server
std::vector<Plaintext> MPDecryptFinal(const CryptoContext& cc, const std::vector<std::vector<RLWE>>& partials) {
    const uint32_t n = partials.size();                            // parties
    const uint32_t m = partials.empty() ? 0 : partials[0].size();  // ciphertexts

    std::vector<Plaintext> pts(m);
    for (uint32_t j = 0; j < m; ++j) {
        std::vector<RLWE> shares;
        shares.reserve(n);
        for (uint32_t i = 0; i < n; ++i) shares.push_back(partials[i][j]);
        cc->MultipartyDecryptFusion(shares, &pts[j]);
    }
    return pts;
}

/// @brief Full decryption of single RGSW (for assertions)
Plaintext MPDecryptFull(const ExtendedContext& cc, const RGSW& ct, const uint32_t n, const PublicKey& jointPk,
                        const std::vector<PrivateKey>& sks) {
    const auto one_pt = cc->MakeCoefPackedPlaintext({1});
    const auto identity = cc->Encrypt(jointPk, one_pt);
    const auto ct_vec = {cc->EvalExternalProduct(identity, ct)};
    const auto partials = MPDecryptPartials(cc, ct_vec, n, sks);
    return MPDecryptFinal(cc, partials)[0];
};


// Fixture: SetUp() handles everything before the Encryption Phase
// (crypto context, chained joint pk, server state matrices, identity ct).
// Each TEST_P below corresponds to one scoped phase from the original flow.
class Multiparty : public ::testing::TestWithParam<uint32_t> {
   protected:
    uint32_t bits = 0;
    uint32_t n = 0;
    uint64_t plaintextModulus = 0;

    ExtendedContext cc;

    std::vector<Client> clients;
    std::vector<PrivateKey> secrets;  // simulation-only: in practice each sk_i stays with its client
    PublicKey jointPk;
    PrivateKey jointSk;  // simulation-only: sum of shards, for noise inspection via PRINT_MAX_NOISE
    server::Matrix<RGSW, 3> I_mat;
    server::Matrix<RLWE, 3> L_mat;
    RLWE identity;  // for EvalExternalProduct-based RGSW->RLWE conversion

    void SetUp() override {
        bits = GetParam();
        ASSERT_GE(bits, 1u) << "Threshold decryption needs at least 2 clients";
        n = (1u << bits);

        auto ccParams = spar::params::Make(spar::params::Set::MultiParty);
        ccParams.SetMultipartyMode(lbcrypto::NOISE_FLOODING_MULTIPARTY);

        plaintextModulus = ccParams.GetPlaintextModulus();

        cc = GenContextBV(ccParams, 3);
        cc->Enable(lbcrypto::PKE);
        cc->Enable(lbcrypto::LEVELEDSHE);
        cc->Enable(lbcrypto::MULTIPARTY);

        // Chained joint pk generation
        clients.resize(n);
        secrets.resize(n);
        clients[0] = {0, cc->KeyGen()};
        secrets[0] = clients[0].kpShard.secretKey;
        for (uint32_t i = 1; i < n; ++i) {
            clients[i].id = i;
            clients[i].kpShard = cc->MultipartyKeyGen(clients[i - 1].kpShard.publicKey);
            secrets[i] = clients[i].kpShard.secretKey;
        }
        for (const auto& c : clients) {
            ASSERT_TRUE(c.kpShard.good()) << "Client " << c.id << " has invalid key shard";
        }

        jointPk = clients[n - 1].kpShard.publicKey;

        // Aggregate secret key (sum of shards) so PRINT_MAX_NOISE can inspect
        // ciphertexts encrypted under the joint public key.
        jointSk = std::make_shared<lbcrypto::PrivateKeyImpl<Poly>>(cc);
        Poly s = secrets[0]->GetPrivateElement();
        for (uint32_t i = 1; i < n; ++i) s += secrets[i]->GetPrivateElement();
        jointSk->SetPrivateElement(std::move(s));

        std::tie(I_mat, L_mat) = server::InitializeState(cc, jointPk, n);

        identity = cc->Encrypt(jointPk, cc->MakeCoefPackedPlaintext({1}));
    }

    // Records ||e||_inf of the noisiest RLWE in L, so every phase leaves behind a
    // CSV row even when it never touches the matrix (a fresh L reads as 0).
    void TearDown() override {
#if defined(DEBUG_LOGGING)
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        // Parameterized names arrive as "<Test>/<Param>"; keep the stem out of the path.
        std::string test(info->name());
        test = test.substr(0, test.find('/'));

        BigInteger maxE(0);
        for (const auto& row : L_mat) {
            for (const auto& ct : row) {
                const auto e = core::utils::MaxNoise(cc, ct, jointSk);
                if (e > maxE) maxE = e;
            }
        }

        RECORD_START("results/Multiparty/" + test + "-N" + std::to_string(n) + ".csv", "n,msb,noise");
        RECORD(n, maxE.GetMSB(), maxE);
        RECORD_END();
#endif
    }

    // Helpers so later phases can reproduce earlier ones in their own TEST_P.
    void RunEncryptOneHot() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> n_dist(0, n - 1);
        const auto bounds = static_cast<int64_t>(plaintextModulus) / 2;

        for (auto& client : clients) {
            client.indices = {OneHot(cc, jointPk, n, n_dist(gen)), OneHot(cc, jointPk, n, n_dist(gen)),
                              OneHot(cc, jointPk, n, n_dist(gen))};
            client.value = cc->Encrypt(jointPk, cc->MakeCoefPackedPlaintext({(client.id + 1) % bounds}));
        }
    }

    void RunServerWrite() {
        for (auto& client : clients) {
            client.failed = server::Write<3, 3>(cc, jointPk, client.value, n, L_mat, I_mat, client.indices);
        }
    }
};

//------------------//
// Encryption Phase //
//------------------//

// Method suggested in paper, requires HomExpand on server (not implemented yet)
TEST_P(Multiparty, EncryptBandwidth) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> n_dist(0, n - 1);

    DEBUG_TIMER("Client: Encrypt (Bandwidth optimized RLWE)");

    for (auto& client : clients) {
        const auto z0 = EncryptBinaryIndicies(cc, jointPk, n, n_dist(gen));
        const auto z1 = EncryptBinaryIndicies(cc, jointPk, n, n_dist(gen));
        const auto z2 = EncryptBinaryIndicies(cc, jointPk, n, n_dist(gen));
        const auto pt = cc->MakeCoefPackedPlaintext({client.id});
    }
}

// Higher bandwidth method, does not require HomExpand
TEST_P(Multiparty, EncryptOneHot) {
    DEBUG_TIMER("Client: Encrypt");
    RunEncryptOneHot();
}

//--------------------//
// Server Write Phase //
//--------------------//

TEST_P(Multiparty, ServerWrite) {
    RunEncryptOneHot();

    DEBUG_TIMER("Server: Write");
    for (auto& client : clients) {
        // TODO: rename failed -> failed
        client.failed = server::Write<3, 3>(cc, jointPk, client.value, n, L_mat, I_mat, client.indices);

        // Track noise growth in the write matrix (L) as each user writes.
        // L holds RGSW ciphertexts, so convert to RLWE via external product with rlwe(1).
        const auto L_slot = L_mat[0][0];
        PRINT_MAX_NOISE(cc, L_slot, jointSk);

        // Verify (not)failed = 0
        Plaintext dec = MPDecryptFull(cc, client.failed, n, jointPk, secrets);
        ASSERT_EQ(dec->GetCoefPackedValue()[0], 0);
    }
}

//------------//
// Decryption //
//------------//

TEST_P(Multiparty, Decryption) {
    RunEncryptOneHot();
    RunServerWrite();

    std::vector<std::vector<RLWE>> partials;
    {
        std::vector<RLWE> ciphertexts;
        ciphertexts.reserve(3 * n);
        for (const auto& bucket : L_mat) {
            for (const auto& rlwe : bucket) {
                ciphertexts.push_back(rlwe);
            }
        }

        DEBUG_TIMER("Client: Partial Decryption");
        partials = MPDecryptPartials(cc, ciphertexts, n, secrets);
    }

    DEBUG_TIMER("Server: Final Decryption");
    auto result = MPDecryptFinal(cc, partials);

    auto numValues = n;
    for (size_t i = 0; i < result.size(); i++) {
        const auto val = result[i]->GetCoefPackedValue()[0];

        // Assert value is between 1 and n or 0; shows there is no noise when n << t/2
        ASSERT_GE(val, 0);
        ASSERT_LE(val, n);

        if (val != 0) numValues--;
    }

    // Verify there are exactly n messages
    ASSERT_EQ(numValues, 0);
}

INSTANTIATE_TEST_SUITE_P(Bits, Multiparty, ::testing::Values(1u, 2u, 3u),
                         [](const auto& info) { return "N" + std::to_string(1u << info.param); });

}  // namespace spar::test
