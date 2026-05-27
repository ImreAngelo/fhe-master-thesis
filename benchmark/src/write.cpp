#include <benchmark/benchmark.h>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

#include "core/context.h"
#include "server/write.h"

namespace {

using namespace lbcrypto;
using core::ExtendedContext;
using core::Plaintext;
using core::PublicKey;
using core::RGSW;
using core::ServerMatrix;

constexpr uint32_t K = 3;
constexpr uint32_t D = 3;

CCParams<CryptoContextBGVRNS> MakeBaseParams() {
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(1);
    params.SetPlaintextModulus(1 << 8);
    params.SetRingDim(1 << 11);
    params.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    params.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);
    params.SetNumLargeDigits(1);
    params.SetStandardDeviation(std::pow(2.0, -55.0));
    return params;
}

struct Fixture {
    uint32_t                N = 0;
    ExtendedContext         cc;
    KeyPair<DCRTPoly>     keys;
    Plaintext               zero_pt;
    Plaintext               one_pt;
    ServerMatrix<RGSW, K>   L_mat;
    ServerMatrix<RGSW, K>   I_mat;
};

Fixture BuildFixture(uint32_t N) {
    Fixture f;
    f.N  = N;
    f.cc = core::GenContextHybrid(MakeBaseParams());
    f.cc->Enable(PKE);
    f.cc->Enable(LEVELEDSHE);
    f.keys = f.cc->KeyGen();

    f.zero_pt = f.cc->MakeCoefPackedPlaintext({0});
    f.one_pt  = f.cc->MakeCoefPackedPlaintext({1});

    f.L_mat.resize(N);
    f.I_mat.resize(N);
    for (uint32_t i = 0; i < N; i++) {
        for (uint32_t k = 0; k < K; k++) {
            f.L_mat[i][k] = f.cc->EncryptRGSW(f.keys.publicKey, f.zero_pt);
            f.I_mat[i][k] = f.cc->EncryptRGSW(f.keys.publicKey, f.one_pt);
        }
    }
    return f;
}

std::vector<std::vector<RGSW>> MakeZ(const Fixture& f, uint32_t target) {
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

        std::vector<Plaintext> Vrs;
        std::vector<std::vector<std::vector<RGSW>>> zs;
        Vrs.reserve(N);
        zs.reserve(N);
        for (uint32_t r = 0; r < N; r++) {
            Vrs.push_back(f.cc->MakeCoefPackedPlaintext({static_cast<int64_t>(r + 1)}));
            zs.push_back(MakeZ(f, r));
        }
        s.ResumeTiming();

        // Per user test - The total runtime is this time * N
        // for (uint32_t r = 0; r < N; r++) {
            auto nothw = spar::server::Write<K, D>(f.cc, f.keys.publicKey, Vrs[0], N, f.L_mat, f.I_mat, zs[0]);
            benchmark::DoNotOptimize(nothw);
        // }
    }
}

void RegisterAll() {
    for (uint32_t N : {2u, 32u, 64u, 128u}) {
        benchmark::RegisterBenchmark("Server/Write/N" + std::to_string(N),
            [N](benchmark::State& s) { WriteBench(s, N); });
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
