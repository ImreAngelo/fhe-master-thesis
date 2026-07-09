#include "core/context.h"
#include "params.h"
#include <benchmark/benchmark.h>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

using namespace lbcrypto;

struct SchemeCase {
    std::string name;
    std::function<core::ExtendedContext()> make;
};

struct Fixture {
    core::ExtendedContext cc;
    KeyPair<DCRTPoly> keys;
    Plaintext pt_msg;
    Ciphertext<DCRTPoly> rlwe_ct;
    std::vector<Ciphertext<DCRTPoly>> rgsw_ct;
};

Fixture BuildFixture(const SchemeCase& sc) {
    Fixture f;
    f.cc = sc.make();
    f.cc->Enable(PKE);
    // f.cc->Enable(LEVELEDSHE);
    f.keys = f.cc->KeyGen();
    f.pt_msg = f.cc->MakeCoefPackedPlaintext({2});
    f.rlwe_ct = f.cc->Encrypt(f.keys.publicKey, f.pt_msg);
    f.rgsw_ct = f.cc->EncryptRGSW(f.keys.publicKey, f.pt_msg);
    return f;
}

const Fixture& GetFixture(const SchemeCase& sc) {
    static std::unordered_map<std::string, Fixture> cache;
    auto it = cache.find(sc.name);
    if (it == cache.end()) it = cache.emplace(sc.name, BuildFixture(sc)).first;
    return it->second;
}

void EncryptBench(benchmark::State& s, const SchemeCase& sc) {
    const auto& f = GetFixture(sc);
    for (auto _ : s) {
        auto c = f.cc->EncryptRGSW(f.keys.publicKey, f.pt_msg);
        benchmark::DoNotOptimize(c);
    }
}

void ExternalProductBench(benchmark::State& s, const SchemeCase& sc) {
    const auto& f = GetFixture(sc);
    for (auto _ : s) {
        auto c = f.cc->EvalExternalProduct(f.rlwe_ct, f.rgsw_ct);
        benchmark::DoNotOptimize(c);
    }
}

void InternalProductBench(benchmark::State& s, const SchemeCase& sc) {
    const auto& f = GetFixture(sc);
    for (auto _ : s) {
        auto c = f.cc->EvalInternalProduct(f.rgsw_ct, f.rgsw_ct);
        benchmark::DoNotOptimize(c);
    }
}

const std::vector<SchemeCase> kSchemes = {
    {"BV", [] { return core::GenContextBV(spar::params::Large(), /*ell=*/3); }},
    // {"Hybrid", [] { return core::GenContextHybrid(spar::params::Large()); }},
};

void RegisterAll() {
    for (const auto& sc : kSchemes) {
        benchmark::RegisterBenchmark("RGSW/Encrypt/" + sc.name, [sc](benchmark::State& s) { EncryptBench(s, sc); });
        benchmark::RegisterBenchmark("RGSW/ExternalProduct/" + sc.name, [sc](benchmark::State& s) { ExternalProductBench(s, sc); });
        benchmark::RegisterBenchmark("RGSW/InternalProduct/" + sc.name, [sc](benchmark::State& s) { InternalProductBench(s, sc); });
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
