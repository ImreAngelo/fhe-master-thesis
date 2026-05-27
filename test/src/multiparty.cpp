#include "openfhe.h"

using namespace lbcrypto;

struct User {
    uint32_t id; // unique ID

    std::vector<Ciphertext<DCRTPoly>> sharesPair;  // (h_{0,i}, h_{1,i}) = (masked decryption
                                                   // share, re-encryption share)
                                                   // we use a vector inseat of std::pair for Python API compatibility

    KeyPair<DCRTPoly> kpShard;  // key-pair shard (pk, sk_i)
};

void OrchestrateRound(uint32_t n) {
    const auto params = params::Small();
    const auto cc = GenCryptoContext(params);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    // Key generation
    std::vector<User> users(n);
    users[0].id = 0;
    users[0].kpShard = cc->KeyGen();

    const auto pk = users[0].kpShard.publicKey;
    for(uint32_t i = 1; i < n; i++) {
        users[i].id = i;
        users[i].kpShard = cc->MultipartyKeyGen(pk);
    }

    std::cout << "Joint public key generated." << std::endl;

    // Generation was successful
    for(const auto& u : users) {
        ASSERT_TRUE(u.kpShard.good());
    }

    std::vector<PrivateKey<DCRTPoly>> secretKeys;
    for (usint i = 0; i < n; i++) {
        secretKeys.push_back(parties[i].kpShard.secretKey);
    }

    KeyPair<DCRTPoly> kpMultiparty = cryptoContext->MultipartyKeyGen(secretKeys);
}

TEST(MP, N4) { OrchestrateRound(4); }