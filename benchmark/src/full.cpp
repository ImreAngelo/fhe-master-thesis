#include <benchmark/benchmark.h>
#include <chrono>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "core/context.h"
#include "server/state.h"
#include "server/write.h"
#include "params.h"

namespace {

using namespace lbcrypto;
using core::ExtendedContext;
using core::Plaintext;
using core::Poly;
using core::PrivateKey;
using core::PublicKey;
using core::RGSW;
using core::RLWE;
using spar::server::Matrix;

constexpr uint32_t K = 3;
constexpr uint32_t D = 3;

struct Client {
    uint32_t                          id;
    KeyPair<Poly>                     kpShard;
    std::vector<std::vector<RGSW>>    indices;
    Plaintext                         value;
    RGSW                              hasWritten;
};

// One-hot indicator of length `len`, with 1 at position `idx`.
std::vector<RGSW> OneHot(const ExtendedContext& cc, const PublicKey& pk,
                         uint32_t len, uint32_t idx) {
    const auto zero_pt = cc->MakeCoefPackedPlaintext({0});
    const auto one_pt  = cc->MakeCoefPackedPlaintext({1});
    std::vector<RGSW> slots(len);
    for (uint32_t i = 0; i < len; ++i) {
        slots[i] = cc->EncryptRGSW(pk, (i == idx) ? one_pt : zero_pt);
    }
    return slots;
}

std::vector<std::vector<RLWE>> MPDecryptPartials(const core::CryptoContext& cc,
                                                 const std::vector<RLWE>& cts,
                                                 uint32_t n,
                                                 const std::vector<PrivateKey>& sks) {
    std::vector<std::vector<RLWE>> partials(n);
    partials[0] = cc->MultipartyDecryptLead(cts, sks[0]);
    for (uint32_t i = 1; i < n; ++i) {
        partials[i] = cc->MultipartyDecryptMain(cts, sks[i]);
    }
    return partials;
}

std::vector<Plaintext> MPDecryptFinal(const core::CryptoContext& cc,
                                      const std::vector<std::vector<RLWE>>& partials) {
    const uint32_t n = partials.size();
    const uint32_t m = partials.empty() ? 0 : partials[0].size();
    std::vector<Plaintext> pts(m);
    for (uint32_t j = 0; j < m; ++j) {
        std::vector<RLWE> shares;
        shares.reserve(n);
        for (uint32_t i = 0; i < n; ++i) shares.push_back(partials[i][j]);
        cc->MultipartyDecryptFusion(shares, &pts[j]);
    }
    return pts;
}

struct Fixture {
    uint32_t                n;
    uint64_t                plaintextModulus;
    ExtendedContext         cc;
    std::vector<Client>     clients;
    std::vector<PrivateKey> secrets;
    PublicKey               jointPk;
    Matrix<K>               I_mat;
    Matrix<K>               L_mat;
    RLWE                    identity;
};

// Everything that the unit-test fixture's SetUp() does: context, chained
// joint pk, state matrices, identity ciphertext.
Fixture BuildFixture(uint32_t n) {
    Fixture f;
    f.n = n;

    auto ccParams      = spar::params::Small();
    f.plaintextModulus = ccParams.GetPlaintextModulus();
    f.cc               = core::GenContextHybrid(ccParams);

    f.cc->Enable(PKE);
    f.cc->Enable(KEYSWITCH);
    f.cc->Enable(LEVELEDSHE);
    f.cc->Enable(ADVANCEDSHE);
    f.cc->Enable(MULTIPARTY);

    f.clients.resize(n);
    f.secrets.resize(n);
    f.clients[0] = {0, f.cc->KeyGen(), {}, {}, {}};
    f.secrets[0] = f.clients[0].kpShard.secretKey;
    for (uint32_t i = 1; i < n; ++i) {
        f.clients[i].id      = i;
        f.clients[i].kpShard = f.cc->MultipartyKeyGen(f.clients[i - 1].kpShard.publicKey);
        f.secrets[i]         = f.clients[i].kpShard.secretKey;
    }

    f.jointPk = f.clients[n - 1].kpShard.publicKey;
    std::tie(f.I_mat, f.L_mat) = spar::server::InitializeStateMatrices(f.cc, f.jointPk, n);
    f.identity = f.cc->Encrypt(f.jointPk, f.cc->MakeCoefPackedPlaintext({1}));

    return f;
}

void EncryptOneHot(Fixture& f) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> n_dist(0, f.n - 1);
    const auto bounds = static_cast<int64_t>(f.plaintextModulus) / 2;

    for (auto& client : f.clients) {
        client.indices = {
            OneHot(f.cc, f.jointPk, f.n, n_dist(gen)),
            OneHot(f.cc, f.jointPk, f.n, n_dist(gen)),
            OneHot(f.cc, f.jointPk, f.n, n_dist(gen))
        };
        client.value = f.cc->MakeCoefPackedPlaintext({(client.id + 1) % bounds});
    }
}

void ServerWrite(Fixture& f) {
    for (auto& client : f.clients) {
        client.hasWritten = spar::server::Write<K, D>(
            f.cc, f.jointPk, client.value, f.n, f.L_mat, f.I_mat, client.indices);
    }
}

// Runs the full pipeline once per iteration; reports per-phase wall time as
// counters. real_time = sum of the four phase totals; each counter is the
// per-iteration average for that phase.
void FullBench(benchmark::State& s, uint32_t bits) {
    const uint32_t n = 1u << bits;
    using clock = std::chrono::steady_clock;
    using ms    = std::chrono::duration<double, std::milli>;

    double t_encrypt = 0, t_write = 0, t_partial = 0, t_fusion = 0;

    for (auto _ : s) {
        s.PauseTiming();
        Fixture f = BuildFixture(n);
        s.ResumeTiming();

        const auto e0 = clock::now();

        // Encryption Phase (one-hot RGSW)
        EncryptOneHot(f);
        const auto e1 = clock::now();

        // Server Write Phase
        ServerWrite(f);
        const auto e2 = clock::now();

        // Partial Decryption (clients)
        std::vector<RLWE> cts;
        cts.reserve(K * n);
        for (auto& bucket : f.L_mat) {
            for (auto& rgsw : bucket) {
                cts.push_back(f.cc->EvalExternalProduct(f.identity, rgsw));
            }
        }
        auto partials = MPDecryptPartials(f.cc, cts, n, f.secrets);
        const auto e3 = clock::now();

        // Final Decryption (server)
        auto result = MPDecryptFinal(f.cc, partials);
        const auto e4 = clock::now();

        benchmark::DoNotOptimize(result);

        t_encrypt += ms(e1 - e0).count();
        t_write   += ms(e2 - e1).count();
        t_partial += ms(e3 - e2).count();
        t_fusion  += ms(e4 - e3).count();
    }

    // Numeric prefix forces execution-order columns under
    // --benchmark_counters_tabular (which sorts std::map keys alphabetically).
    using benchmark::Counter;
    s.counters["1. Encrypt"]        = Counter(t_encrypt, Counter::kAvgIterations);
    s.counters["2. Write"]          = Counter(t_write,   Counter::kAvgIterations);
    s.counters["3. Partial Dec."]   = Counter(t_partial, Counter::kAvgIterations);
    s.counters["4. Final Dec."]     = Counter(t_fusion,  Counter::kAvgIterations);
}

void RegisterAll() {
    for (uint32_t bits : {1u, 5u, 6u, 7u}) {
        const uint32_t n = 1u << bits;
        benchmark::RegisterBenchmark(
            "Multiparty/Full/N" + std::to_string(n),
            [bits](benchmark::State& s) { FullBench(s, bits); })
            ->Unit(benchmark::kMillisecond);
    }
}

} // namespace

int main(int argc, char** argv) {
    benchmark::Initialize(&argc, argv);
    RegisterAll();
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
