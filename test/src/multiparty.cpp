#include "core/context.h"
#include "openfhe.h"

namespace spar::test {

// using namespace lbcrypto;

struct Client {
    uint32_t id;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> kpShard;  // (joint pk after i's contribution, sk_i)
};

void OrchestrateRound(uint32_t n) {
    ASSERT_GE(n, 2u) << "Threshold decryption needs at least 2 clients";

    const auto params = params::Small();
    const auto cc = GenContextHybrid(params);

    cc->Enable(lbcrypto::PKE);
    cc->Enable(lbcrypto::KEYSWITCH);
    cc->Enable(lbcrypto::LEVELEDSHE);
    cc->Enable(lbcrypto::ADVANCEDSHE);
    cc->Enable(lbcrypto::MULTIPARTY);

    // Joint public key generation
    std::vector<Client> clients(n);
    clients[0] = {0, cc->KeyGen()};

    for (uint32_t i = 1; i < n; ++i) {
        clients[i].id = i;
        clients[i].kpShard = cc->MultipartyKeyGen(clients[i - 1].kpShard.publicKey);
    }

    for (const auto& c : clients) {
        ASSERT_TRUE(c.kpShard.good()) << "Client " << c.id << " has invalid key shard";
    }

    // The joint pk lives on the last link of the chain. Anyone (server, any client, an external producer) may hold it to encrypt.
    const auto jointPk = clients[n - 1].kpShard.publicKey;
    const auto joinTag = jointPk->GetKeyTag();

    // Encryption under the joint pk
    const std::vector<int64_t> values{2};
    const auto pt = cc->MakeCoefPackedPlaintext(values);
    const auto ct = cc->EncryptRGSW(jointPk, pt);
    const auto rlwe = cc->Encrypt(jointPk, pt);

    // Server-side homomorphic evaluation
    const auto res = cc->EvalExternalProduct(rlwe, ct);
    using RLWECiphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;

    // Partial decryption: client 0 is Lead, others are Main
    std::vector<std::vector<RLWECiphertext>> partials(n);
    partials[0] = cc->MultipartyDecryptLead({res}, clients[0].kpShard.secretKey);
    for (uint32_t i = 1; i < n; ++i) {
        partials[i] = cc->MultipartyDecryptMain({res}, clients[i].kpShard.secretKey);
    }

    // Server fuses the n partials
    std::vector<RLWECiphertext> shares;
    shares.reserve(n);
    for (uint32_t i = 0; i < n; ++i) shares.push_back(partials[i][0]);

    lbcrypto::Plaintext result;
    cc->MultipartyDecryptFusion(shares, &result);

    // Verify result
    const std::vector<int64_t> expected{4};
    auto expectedPt = cc->MakeCoefPackedPlaintext(expected);
    expectedPt->SetLength(expected.size());
    result->SetLength(expected.size());
    EXPECT_EQ(result, expectedPt);
}

TEST(MP, N2) { OrchestrateRound(2); }
// TEST(MP, N4) { OrchestrateRound(4); }
// TEST(MP, N8) { OrchestrateRound(8); }

} // namespace spar::test
