#include "server/write.h"
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using namespace lbcrypto;
using core::ExtendedContext;
using core::Plaintext;
using core::PublicKey;
using core::RGSW;
using core::RLWE;
using spar::server::Matrix;

constexpr uint32_t K = 3;
constexpr uint32_t D = 3;

struct Fixture {
    uint32_t N = 0;
    ExtendedContext cc;
    KeyPair<DCRTPoly> keys;
    Plaintext zero_pt;
    Plaintext one_pt;
    Matrix<RLWE, K> L_mat;
    Matrix<RGSW, K> I_mat;
};

Fixture BuildFixture(uint32_t N) {
    Fixture f;
    f.N = N;
    // WARN: Hybrid does not support the internal product yet, so this uses
    // whichever scheme params.toml declares (bv).
    f.cc = spar::params::MakeContext(spar::params::Resolve());
    f.keys = spar::utils::MakeKeys(f.cc);

    f.zero_pt = f.cc->MakeCoefPackedPlaintext({0});
    f.one_pt = f.cc->MakeCoefPackedPlaintext({1});

    f.L_mat.resize(N);
    f.I_mat.resize(N);
    for (uint32_t i = 0; i < N; i++) {
        for (uint32_t k = 0; k < K; k++) {
            f.L_mat[i][k] = f.cc->Encrypt(f.keys.publicKey, f.zero_pt);
            f.I_mat[i][k] = f.cc->EncryptRGSW(f.keys.publicKey, f.one_pt);
        }
    }
    return f;
}

std::vector<std::vector<RGSW>> MakeZ(const Fixture& f, uint32_t target = 4) {
    std::vector<RGSW> hot(f.N);
    for (uint32_t i = 0; i < f.N; i++) {
        hot[i] = f.cc->EncryptRGSW(f.keys.publicKey, (i == target) ? f.one_pt : f.zero_pt);
    }
    return std::vector<std::vector<RGSW>>(D, hot);
}

void WriteBench(benchmark::State& s, uint32_t N) {
    for (auto _ : s) {
        s.PauseTiming();
        Fixture f = BuildFixture(N);

        auto val = f.cc->MakeCoefPackedPlaintext({2});
        auto Vr = f.cc->Encrypt(f.keys.publicKey, val);
        auto z = MakeZ(f);
        s.ResumeTiming();

        // Per user test - The total runtime is this time * N
        auto nothw = spar::server::Write<3, 3>(f.cc, f.keys.publicKey, Vr, N, f.L_mat, f.I_mat, z);
        benchmark::DoNotOptimize(nothw);
    }
}

void RegisterAll() {
    for (uint32_t N : {
             2u, 4u, 8u, 16u, 32u, 64u,  // 128u
         }) {
        benchmark::RegisterBenchmark("Server/Write/N" + std::to_string(N), [N](benchmark::State& s) { WriteBench(s, N); });
    }
}

}  // namespace

int main(int argc, char** argv) {
    benchmark::Initialize(&argc, argv);
    RegisterAll();
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
