#include <gtest/gtest.h>
#include "core/context.h"
#include "core/types.h"
#include "core/utils/timer.h"
#include "key/publickey-fwd.h"
#include "server/state.h"
#include "server/write.h"
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
    Plaintext value;
    RGSW hasWritten;
};

/// @brief Encrypts a one-hot indicator of length `len` with the 1 at position `idx`
std::vector<RGSW> OneHot(const ExtendedContext& cc, const PublicKey& pk, const uint32_t len, const uint32_t idx) {
    const auto zero_pt = cc->MakeCoefPackedPlaintext({0});
    const auto one_pt  = cc->MakeCoefPackedPlaintext({1});

    // std::cout << idx << ", ";

    std::vector<RGSW> slots(len);
    for(uint32_t i = 0; i < len; i++) {
        slots[i] = cc->EncryptRGSW(pk, (i == idx) ? one_pt : zero_pt);
    }
    return slots;
}

/// @brief Client encryption matching bandwidth-optimized scenario from paper
template<typename T = uint32_t>
std::vector<RLWE> EncryptBinaryIndicies(const CryptoContext& cc, const PublicKey& pk, uint32_t l, T idx) {
    // static_assert(sizeof(T) >= length, "");
    // TODO: Assert idx can be represented by l bits

    std::bitset<sizeof(T)> bits;
    std::vector<RLWE> encrypted(l);

    for(uint32_t i = 0; i < l; i++) {
        const auto bit_pt = cc->MakeCoefPackedPlaintext({ bits[i] });
        encrypted[i] = cc->Encrypt(pk, bit_pt);
    }

    return encrypted;
}

/// @brief Partial decryption by all clients
std::vector<std::vector<RLWE>> MPDecryptPartials(const CryptoContext& cc, const std::vector<RLWE> &cts, const uint32_t n, const std::vector<PrivateKey>& sks) {
    std::vector<std::vector<RLWE>> partials(n);

    partials[0] = cc->MultipartyDecryptLead(cts, sks[0]);
    for(uint32_t i = 1; i < n; i++) {
        partials[i] = cc->MultipartyDecryptMain(cts, sks[i]);
    }

    return partials;
}

/// @brief Final decryption by server
std::vector<Plaintext> MPDecryptFinal(const CryptoContext& cc, const std::vector<std::vector<RLWE>>& partials) {
    const uint32_t n = partials.size(); // parties
    const uint32_t m = partials.empty() ? 0 : partials[0].size(); // ciphertexts

    std::vector<Plaintext> pts(m);
    for (uint32_t j = 0; j < m; ++j) {
        std::vector<RLWE> shares;
        shares.reserve(n);
        for (uint32_t i = 0; i < n; ++i)
            shares.push_back(partials[i][j]);
        cc->MultipartyDecryptFusion(shares, &pts[j]);
    }
    return pts;
}

/// @brief Full decryption of single RGSW (for assertions)
Plaintext MPDecryptFull(const ExtendedContext& cc, const RGSW& ct, const uint32_t n, const PublicKey& jointPk, const std::vector<PrivateKey>& sks) {
    const auto one_pt = cc->MakeCoefPackedPlaintext({1});
    const auto identity = cc->Encrypt(jointPk, one_pt);
    const auto ct_vec = {cc->EvalExternalProduct(identity, ct)};
    const auto partials = MPDecryptPartials(cc, ct_vec, n, sks);
    return MPDecryptFinal(cc, partials)[0];
};


void OrchestrateRound(const uint32_t bits) {
    ASSERT_GE(bits, 1u) << "Threshold decryption needs at least 2 clients";
    const uint32_t n = (1 << bits);

    const auto params = params::Small();
    const auto cc = GenContextHybrid(params);

    cc->Enable(lbcrypto::PKE);
    cc->Enable(lbcrypto::KEYSWITCH);
    cc->Enable(lbcrypto::LEVELEDSHE);
    cc->Enable(lbcrypto::ADVANCEDSHE);
    cc->Enable(lbcrypto::MULTIPARTY);

    // In practice each secret key is only know by the client, but for simulation all clients are the same orchestrator
    std::vector<PrivateKey> secrets(n);

    // Joint public key generation
    std::vector<Client> clients(n);
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

    // The joint pk lives on the last link of the chain
    const auto jointPk = clients[n - 1].kpShard.publicKey;
    const auto joinTag = jointPk->GetKeyTag();

    // Set up server state
    auto [I_mat, L_mat] = server::InitializeStateMatrices(cc, jointPk, n);

    // Helper for decryption using EvalExternalProduct
    const auto one_pt = cc->MakeCoefPackedPlaintext({1});
    const auto identity = cc->Encrypt(jointPk, one_pt);

    //------------------//
    // Encryption Phase //
    //------------------//

    { /* Method suggested in paper, requires HomExpand on server (not implemented yet) */
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> n_dist(0, n-1);

        DEBUG_TIMER("Client: Encrypt (Bandwidth optimized RLWE)");

        for(auto& client : clients) {
            const auto z0 = EncryptBinaryIndicies(cc, jointPk, n, n_dist(gen));
            const auto z1 = EncryptBinaryIndicies(cc, jointPk, n, n_dist(gen));
            const auto z2 = EncryptBinaryIndicies(cc, jointPk, n, n_dist(gen));
            const auto pt = cc->MakeCoefPackedPlaintext({client.id});
        }
    }

    { /* Higher bandwidth method, does not require HomExpand */
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> n_dist(0, n-1);

        const auto bounds = static_cast<int64_t>(params.GetPlaintextModulus())/2;
        // std::uniform_int_distribution<int64_t> pt_dist(-bounds, bounds - 1);
        // DEBUG_PRINT("Bounds: [" << -bounds << ", " << bounds << ")");

        DEBUG_TIMER("Client: Encrypt");

        for(auto& client : clients) {
            // std::cout << "Client " << (client.id + 1) << ": ";
            client.indices = {
                OneHot(cc, jointPk, n, n_dist(gen)),
                OneHot(cc, jointPk, n, n_dist(gen)),
                OneHot(cc, jointPk, n, n_dist(gen))
            };
            client.value = cc->MakeCoefPackedPlaintext({(client.id + 1) % bounds});
            // std::cout << std::endl;
        }
    }

    //--------------------//
    // Server Write Phase //
    //--------------------//

    {
        DEBUG_TIMER("Server: Write");

        for(auto& client : clients) {
            // TODO: rename hasWritten -> failed
            client.hasWritten = server::Write<3,3>(cc, jointPk, client.value, n, L_mat, I_mat, client.indices);

            // Verify (not)HasWritten = 0
            Plaintext dec = MPDecryptFull(cc, client.hasWritten, n, jointPk, secrets);
            ASSERT_EQ(dec->GetCoefPackedValue()[0], 0);
        }
    }


    //--------------------//
    // Partial Decryption //
    //--------------------//

    std::vector<std::vector<RLWE>> partials;

    {
        std::vector<RLWE> ciphertexts;
        ciphertexts.reserve(3*n);

        for(const auto& bucket : L_mat) {
            for(const auto& rgsw : bucket) {
                ciphertexts.push_back(cc->EvalExternalProduct(identity, rgsw));
            }
        }

        DEBUG_TIMER("Client: Partial Decryption");
        partials = MPDecryptPartials(cc, ciphertexts, n, secrets);
    }

    //-------------------//
    // Server Decryption //
    //-------------------//

    {
        DEBUG_TIMER("Server: Final Decryption");
        auto result = MPDecryptFinal(cc, partials);

        auto numValues = n;
        for (size_t i = 0; i < result.size(); i++) {
            const auto val = result[i]->GetCoefPackedValue()[0];

            // Assert value is between 1 and n or 0, should show there is no noise when n << t/2
            ASSERT_GE(val, 0);
            ASSERT_LE(val, n);

            if(val != 0) {
                numValues--;
            }

            result[i]->SetLength(1);
            // std::cout << result[i] << " ";
            // if((i + 1) % 3 == 0) std::cout << "\n";
        }

        // There are exactly n messages
        ASSERT_EQ(numValues, 0);
    }
}

TEST(MP, N2)   { OrchestrateRound(1); }
TEST(MP, N4)   { OrchestrateRound(2); }
TEST(MP, N8)   { OrchestrateRound(3); }
// TEST(MP, N32)  { OrchestrateRound(5); }
// TEST(MP, N64)  { OrchestrateRound(6); }
// TEST(MP, N128) { OrchestrateRound(7); }

} // namespace spar::test
