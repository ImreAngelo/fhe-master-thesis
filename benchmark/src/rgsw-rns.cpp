/**
 * @file rgsw-rns.cpp
 * @brief Benchmark RGSW encryption and operations in RNS mode
 */

#include "openfhe.h"
#include "core/context.h"

#include <benchmark/benchmark.h>

using namespace lbcrypto;

namespace {

constexpr uint32_t DEPTH        = 3;
constexpr uint32_t RING_DIM_LOG = 14;
constexpr uint64_t PT_MODULUS   = 65537;

CCParams<CryptoContextRGSWBGV> MakeParams() {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(DEPTH);
    params.SetPlaintextModulus(PT_MODULUS);
    params.SetRingDim(1 << RING_DIM_LOG);
    params.SetNumLargeDigits(2);
    params.SetScalingTechnique(FIXEDMANUAL);
    return params;
}

class RGSW_RNS : public benchmark::Fixture {
public:
    void SetUp(const benchmark::State&) override {
        if (cc) return;
        cc = Context::GenExtendedCryptoContext(MakeParams());
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);

        keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        pt_one   = cc->MakePackedPlaintext({ 1 });
        pt_msg   = cc->MakePackedPlaintext({ 2 });
        pt_scale = cc->MakePackedPlaintext({ 3 });

        rlwe_ct = cc->Encrypt(keys.publicKey, pt_one);
        rgsw_ct = cc->EncryptRGSW(keys.secretKey, pt_msg);
    }

    Context::ExtendedCryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly>        keys;
    Plaintext                pt_one, pt_msg, pt_scale;
    Ciphertext<DCRTPoly>     rlwe_ct;
    RGSWCiphertext<DCRTPoly> rgsw_ct;
};

} // namespace

#define MAKE_BENCHMARK(name, cmd) BENCHMARK_F(RGSW_RNS, name)(benchmark::State& s) { \
    for (auto _ : s) { \
        auto c = cmd; \
        benchmark::DoNotOptimize(c); \
    } \
}


MAKE_BENCHMARK(Encrypt, cc->EncryptRGSW(keys.secretKey, pt_msg))
MAKE_BENCHMARK(ExternalProduct, cc->EvalExternalProduct(rlwe_ct, rgsw_ct))
MAKE_BENCHMARK(InternalProduct, cc->EvalInternalProduct(rgsw_ct, rgsw_ct))
MAKE_BENCHMARK(PlaintextMult, cc->EvalMultPlain(pt_scale, rgsw_ct))

BENCHMARK_MAIN();
