// Benchmark RGSW encryption, external product, and internal product.
//
// All ops share one CryptoContext + KeyPair built once in SetUp(); only the
// op itself runs inside the timed loop. To run a subset:
//   ./bench-rgsw --benchmark_filter=ExternalProduct

#include <benchmark/benchmark.h>
#include "openfhe.h"
#include "core/include/context.h"

using namespace lbcrypto;

namespace {
    
class RGSW : public benchmark::Fixture {
    public:
    void SetUp(const benchmark::State&) override {
        if (cc) return;
            
        // TODO: Unified set of params cross-project
        CCParams<CryptoContextBGVRNS> params;
        params.SetMultiplicativeDepth(3);
        params.SetPlaintextModulus(1 << 8);
        params.SetRingDim(1 << 11);
        params.SetScalingTechnique(FIXEDMANUAL);
        params.SetSecurityLevel(SecurityLevel::HEStd_NotSet);

        // Large params (about ~ 8x slower internal products)
        // params.SetMultiplicativeDepth(1);
        // params.SetPlaintextModulus(65537);
        // params.SetRingDim(1 << 14);
        // params.SetScalingTechnique(FIXEDMANUAL);
        
        // Tuneable parameter
        // params.SetNumLargeDigits(2);

        cc = Context::GenExtendedCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);

        keys = cc->KeyGen();
        
        pt_one   = cc->MakeCoefPackedPlaintext({ 1 });
        pt_msg   = cc->MakeCoefPackedPlaintext({ 2 });
        pt_scale = cc->MakeCoefPackedPlaintext({ 3 });

        rlwe_ct = cc->Encrypt(keys.publicKey, pt_one);
        rgsw_ct = cc->EncryptRGSW(keys.publicKey, pt_msg);
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


MAKE_BENCHMARK(Encrypt, cc->EncryptRGSW(keys.publicKey, pt_msg))
MAKE_BENCHMARK(ExternalProduct, cc->EvalExternalProduct(rlwe_ct, rgsw_ct))
MAKE_BENCHMARK(InternalProduct, cc->EvalInternalProduct(rgsw_ct, rgsw_ct))

BENCHMARK_MAIN();
