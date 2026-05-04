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
constexpr uint32_t RING_DIM_LOG = 14;
constexpr uint64_t PT_MODULUS   = 65537;

constexpr uint32_t B_LOG = 10;

CCParams<CryptoContextRGSWBGV> MakeParams() {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(DEPTH);
    params.SetPlaintextModulus(PT_MODULUS);
    params.SetRingDim(1 << RING_DIM_LOG);
    params.SetNumLargeDigits(2);
    params.SetScalingTechnique(FIXEDMANUAL);
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
        
        pt_one   = cc->MakePackedPlaintext({ 1 });
        pt_msg   = cc->MakePackedPlaintext({ 2 });
        pt_scale = cc->MakePackedPlaintext({ 3 });

        rlwe_ct = cc->Encrypt(keys.publicKey, pt_one);
        rgsw_ct = cc->Encrypt_Textbook(keys.publicKey, pt_msg, B_LOG, ell);
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


MAKE_BENCHMARK(Encrypt, cc->Encrypt_Textbook(keys.publicKey, pt_msg, B_LOG, ell))
MAKE_BENCHMARK(ExternalProduct, cc->EvalExternalProduct_Textbook(rlwe_ct, rgsw_ct, ell))
MAKE_BENCHMARK(InternalProduct, cc->EvalInternalProduct_Textbook(rgsw_ct, rgsw_ct, ell))

BENCHMARK_MAIN();
