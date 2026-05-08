// Benchmark RGSW encryption, external product, and internal product.
//
// All ops share one CryptoContext + KeyPair built once in SetUp(); only the
// op itself runs inside the timed loop. To run a subset:
//   ./bench-rgsw --benchmark_filter=ExternalProduct

#include <benchmark/benchmark.h>
#include "openfhe.h"
#include "core/context.h"

using namespace lbcrypto;

namespace {

constexpr uint32_t DEPTH        = 3;
constexpr uint64_t PT_MODULUS   = 8;
constexpr uint32_t RING_DIM_LOG = 11;   // 2048
constexpr uint32_t B_LOG = 15;          // 32768

CCParams<CryptoContextRGSWBGV> MakeParams() {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(DEPTH);
    params.SetPlaintextModulus(PT_MODULUS);
    params.SetRingDim(1 << RING_DIM_LOG);
    // params.SetNumLargeDigits(2);
    // params.SetScalingTechnique(FIXEDMANUAL);
    params.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    return params;
}

class RGSW : public benchmark::Fixture {
public:
    void SetUp(const benchmark::State&) override {
        if (cc) return;
        cc = Context::GenExtendedCryptoContext(MakeParams());
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);

        const size_t log_q = cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB();
        ell = log_q / B_LOG + 1;

        keys = cc->KeyGen();
        
        pt_one   = cc->MakeCoefPackedPlaintext({ 1 });
        pt_msg   = cc->MakeCoefPackedPlaintext({ 2 });
        pt_scale = cc->MakeCoefPackedPlaintext({ 3 });

        rlwe_ct = cc->Encrypt(keys.publicKey, pt_one);
        rgsw_ct = cc->EncryptRGSW(keys.publicKey, pt_msg, B_LOG, ell);
    }

    Context::ExtendedCryptoContext<DCRTPoly> cc;
    std::vector<Ciphertext<DCRTPoly>> rgsw_ct;
    Plaintext                pt_one, pt_msg, pt_scale;
    Ciphertext<DCRTPoly>     rlwe_ct;
    KeyPair<DCRTPoly>        keys;
    size_t ell;
};

} // namespace

#define MAKE_BENCHMARK(name, cmd) BENCHMARK_F(RGSW, name)(benchmark::State& s) { \
    for (auto _ : s) { \
        auto c = cmd; \
        benchmark::DoNotOptimize(c); \
    } \
}


MAKE_BENCHMARK(Encrypt, cc->EncryptRGSW(keys.publicKey, pt_msg, B_LOG, ell))
MAKE_BENCHMARK(ExternalProduct, cc->EvalExternalProduct(rlwe_ct, rgsw_ct, B_LOG))
MAKE_BENCHMARK(InternalProduct, cc->EvalInternalProduct(rgsw_ct, rgsw_ct, B_LOG))

BENCHMARK_MAIN();
