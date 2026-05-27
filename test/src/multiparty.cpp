#include "core/context.h"

namespace spar::test {

using namespace lbcrypto;

struct Client {
    uint32_t id;
    KeyPair<DCRTPoly> kpShard;  // (joint pk after i's contribution, sk_i)
};

// Drives one full n-of-n threshold round:
//   chained joint-pk gen -> joint EvalMult key -> encrypt -> server EvalMult
//   -> per-client partial decryption -> server fusion -> verify
void OrchestrateRound(uint32_t n) {
    ASSERT_GE(n, 2u) << "Threshold decryption needs at least 2 clients";

    const auto params = params::Small<CryptoContextBGVRNS>(2);
    auto cc = GenCryptoContext(params);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    // ---- 1. Joint public-key generation (sequential chain) ----
    std::vector<Client> clients(n);
    clients[0] = {0, cc->KeyGen()};
    for (uint32_t i = 1; i < n; ++i) {
        clients[i].id = i;
        clients[i].kpShard = cc->MultipartyKeyGen(clients[i - 1].kpShard.publicKey);
    }
    for (const auto& c : clients) {
        ASSERT_TRUE(c.kpShard.good()) << "Client " << c.id << " key shard invalid";
    }

    // The joint pk lives on the last link of the chain. Anyone (server, any
    // client, an external producer) may hold it to encrypt.
    const auto jointPk = clients[n - 1].kpShard.publicKey;
    const auto joinTag = jointPk->GetKeyTag();

    // ---- 2. Joint EvalMult key (needed because we will EvalMult) ----
    // Phase A: client 0 makes a local relin-key, the rest produce shares against it.
    std::vector<EvalKey<DCRTPoly>> emk(n);
    emk[0] = cc->KeySwitchGen(clients[0].kpShard.secretKey, clients[0].kpShard.secretKey);
    for (uint32_t i = 1; i < n; ++i) {
        emk[i] = cc->MultiKeySwitchGen(clients[i].kpShard.secretKey,
                                       clients[i].kpShard.secretKey, emk[0]);
    }

    // Phase B: aggregate shares -> relin key for s = sum(s_i), still encrypted under s_0.
    auto evalMultAgg = emk[0];
    for (uint32_t i = 1; i < n; ++i) {
        evalMultAgg = cc->MultiAddEvalKeys(evalMultAgg, emk[i],
                                           clients[i].kpShard.publicKey->GetKeyTag());
    }

    // Phase C: each client re-encrypts the aggregate under the joint pk, then sum.
    std::vector<EvalKey<DCRTPoly>> emkJoint(n);
    for (uint32_t i = 0; i < n; ++i) {
        emkJoint[i] = cc->MultiMultEvalKey(clients[i].kpShard.secretKey, evalMultAgg, joinTag);
    }
    auto evalMultFinal = emkJoint[0];
    for (uint32_t i = 1; i < n; ++i) {
        evalMultFinal = cc->MultiAddEvalMultKeys(evalMultFinal, emkJoint[i], joinTag);
    }
    cc->InsertEvalMultKey({evalMultFinal});

    // ---- 3. Encryption under the joint pk ----
    const std::vector<int64_t> values{1, 2, 3, 4};
    auto pt = cc->MakeCoefPackedPlaintext(values);
    auto ct = cc->Encrypt(jointPk, pt);

    // ---- 4. Server-side homomorphic evaluation ----
    auto ctSq = cc->EvalMult(ct, ct);

    // ---- 5. Partial decryption: client 0 is Lead, the rest are Main ----
    std::vector<std::vector<Ciphertext<DCRTPoly>>> partials(n);
    partials[0] = cc->MultipartyDecryptLead({ctSq}, clients[0].kpShard.secretKey);
    for (uint32_t i = 1; i < n; ++i) {
        partials[i] = cc->MultipartyDecryptMain({ctSq}, clients[i].kpShard.secretKey);
    }

    // ---- 6. Server fuses the n partials ----
    std::vector<Ciphertext<DCRTPoly>> shares;
    shares.reserve(n);
    for (uint32_t i = 0; i < n; ++i) shares.push_back(partials[i][0]);

    Plaintext result;
    cc->MultipartyDecryptFusion(shares, &result);

    // ---- 7. Verify against the polynomial square of {1,2,3,4} ----
    // Coef encoding: ct represents 1 + 2x + 3x^2 + 4x^3, so ct*ct yields
    // 1 + 4x + 10x^2 + 20x^3 + 25x^4 + 24x^5 + 16x^6 (no cyclotomic wrap at this degree).
    const std::vector<int64_t> expected{1, 4, 10, 20, 25, 24, 16};
    auto expectedPt = cc->MakeCoefPackedPlaintext(expected);
    expectedPt->SetLength(expected.size());
    result->SetLength(expected.size());
    EXPECT_EQ(result, expectedPt);
}

TEST(MP, N2) { OrchestrateRound(2); }
TEST(MP, N4) { OrchestrateRound(4); }
TEST(MP, N8) { OrchestrateRound(8); }

} // namespace spar::test
