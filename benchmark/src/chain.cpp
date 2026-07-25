/**
 * @file chain.cpp
 * @brief Noise measurement, not a timing benchmark: chains external/internal
 *        products until decryption fails, recording ||e||_inf at every step.
 *
 * Ported here from test/src/rgsw.cpp — a long noise sweep is not a unit test.
 *
 * The CSVs are the deliverable, so they are written UNCONDITIONALLY via
 * spar::utils::Record* rather than the RECORD_* macros: benchmarks always build
 * with DEBUG_LOGGING=OFF (see benchmark/Makefile), which compiles those macros
 * away entirely.
 *
 * `ell` is the sweep variable and the only parameter that varies here; everything
 * else comes from params.toml. Output goes to benchmark/results/, which
 * `make data` copies into the thesis under Data/Noise/.
 */
#include "spar/noise.h"
#include "spar/record.h"
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

using namespace lbcrypto;
using spar::params::Scheme;

/// Noise scales with message magnitude; chain binary plaintexts.
constexpr int64_t kVal = 1;

/// The BV gadget digit counts to sweep. Ignored by the hybrid gadget, which
/// decomposes per RNS limb, so the hybrid chain is registered once without a suffix.
const std::vector<uint32_t> kEll = {1, 2, 3, 4, 5};

/// Chain length. Shorter than a full run makes a quick smoke test:
///   SPAR_CHAIN_ITERATIONS=20 make bench-chain
int ChainIterations() {
    if (const char* value = std::getenv("SPAR_CHAIN_ITERATIONS")) return std::atoi(value);
    return 300;
}

/// Absolute, for the same reason params.toml's path is: the binary must write to
/// the same place regardless of the directory it is invoked from.
std::string CsvPath(const std::string& kind, const std::string& stem) {
    return std::string(SPAR_BENCH_RESULTS_DIR) + "/" + kind + "/" + stem + ".csv";
}

struct Fixture {
    core::ExtendedContext cc;
    KeyPair<DCRTPoly> keys;
    Plaintext pt_one;
    int64_t t = 0;
};

Fixture Build(const Scheme scheme, const uint32_t ell) {
    auto set = spar::params::Resolve();
    set.ell = ell;  // the sweep variable

    Fixture f;
    f.cc = spar::params::MakeContext(set, scheme);
    f.keys = spar::utils::MakeKeys(f.cc);
    f.pt_one = f.cc->MakeCoefPackedPlaintext({kVal});
    f.t = f.cc->GetCryptoParameters()->GetPlaintextModulus();
    return f;
}

int64_t FirstCoef(const Fixture& f, const RLWE& ct) {
    Plaintext decrypted;
    f.cc->Decrypt(f.keys.secretKey, ct, &decrypted);
    decrypted->SetLength(1);
    const auto& coef = decrypted->GetCoefPackedValue();
    return coef.empty() ? 0 : coef[0];
}

/// @returns how many products still decrypted correctly.
int ExternalChain(const Fixture& f, const std::string& csv, const int maxN) {
    auto current = f.cc->Encrypt(f.keys.publicKey, f.pt_one);
    int64_t expected = 1;
    int last_ok = 0;

    spar::utils::RecordStart(csv, "n,msb,noise");
    for (int n = 1; n <= maxN; ++n) {
        const auto mult = f.cc->EncryptRGSW(f.keys.publicKey, f.pt_one);
        current = f.cc->EvalExternalProduct(current, mult);

        const auto e = spar::utils::MaxNoise(f.cc, current, f.keys.secretKey);
        spar::utils::RecordRow(n, e.GetMSB(), e);

        expected = (expected * kVal) % f.t;
        if (expected > f.t / 2) expected -= f.t;

        if (FirstCoef(f, current) != expected) break;
        last_ok = n;
    }
    spar::utils::RecordEnd();
    return last_ok;
}

/// @returns how many products still decrypted correctly.
int InternalChain(const Fixture& f, const std::string& csv, const int maxN) {
    const auto rgsw_mult = f.cc->EncryptRGSW(f.keys.publicKey, f.pt_one);
    const auto rlwe_one = f.cc->Encrypt(f.keys.publicKey, f.pt_one);

    auto current = f.cc->EncryptRGSW(f.keys.publicKey, f.pt_one);
    int64_t expected = 1;
    int last_ok = 0;

    spar::utils::RecordStart(csv, "n,msb,noise");
    for (int n = 1; n <= maxN; ++n) {
        // The accumulated operand must be the lhs: the rhs of EvalInternalProduct
        // takes the digit-decomposition noise blowup.
        current = f.cc->EvalInternalProduct(current, rgsw_mult);
        const auto res = f.cc->EvalExternalProduct(rlwe_one, current);

        const auto e = spar::utils::MaxNoise(f.cc, res, f.keys.secretKey);
        spar::utils::RecordRow(n, e.GetMSB(), e);

        expected = (expected * kVal) % f.t;
        if (expected > f.t / 2) expected -= f.t;

        if (FirstCoef(f, res) != expected) break;
        last_ok = n;
    }
    spar::utils::RecordEnd();
    return last_ok;
}

/// One Google Benchmark iteration is a whole chain, which far exceeds the default
/// minimum time, so Google Benchmark settles on a single iteration by itself.
/// Rewriting the CSV on a repeat is idempotent.
void ChainBench(benchmark::State& s, const Scheme scheme, const uint32_t ell, const bool internal, const std::string& stem) {
    const Fixture f = Build(scheme, ell);
    const int maxN = ChainIterations();

    int length = 0;
    for (auto _ : s) {
        length = internal ? InternalChain(f, CsvPath("InternalProd", stem), maxN) : ExternalChain(f, CsvPath("ExternalProd", stem), maxN);
    }

    s.counters["ell"] = benchmark::Counter(ell);
    s.counters["chain"] = benchmark::Counter(length);  // products before decryption failed
}

void RegisterAll() {
    for (const uint32_t ell : kEll) {
        const std::string stem = "bv_" + std::to_string(ell);
        benchmark::RegisterBenchmark("Noise/ExternalProduct/" + stem, [ell, stem](benchmark::State& s) {
            ChainBench(s, Scheme::BV, ell, false, stem);
        })->Unit(benchmark::kMillisecond);
        benchmark::RegisterBenchmark("Noise/InternalProduct/" + stem, [ell, stem](benchmark::State& s) {
            ChainBench(s, Scheme::BV, ell, true, stem);
        })->Unit(benchmark::kMillisecond);
    }

    // The hybrid gadget ignores ell and has no internal product, so it gets one
    // unsuffixed external chain.
    benchmark::RegisterBenchmark("Noise/ExternalProduct/hybrid", [](benchmark::State& s) {
        ChainBench(s, Scheme::Hybrid, 1, false, "hybrid");
    })->Unit(benchmark::kMillisecond);
}

}  // namespace

int main(int argc, char** argv) {
    benchmark::Initialize(&argc, argv);
    RegisterAll();
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
