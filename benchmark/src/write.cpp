// TODO: Clean up everything
#define ASSERT_EQ(a, b)

#include <benchmark/benchmark.h>
#include "openfhe.h"
#include "server/server.h"

using namespace lbcrypto;


class ServerWrite : public benchmark::Fixture {
public:
    void SetUp(const benchmark::State&) override {
        params.SetMultiplicativeDepth(1);
        params.SetPlaintextModulus(1 << 8); // 65537
        params.SetRingDim(1 << 11);         // 1 << 14
        params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);
        params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_NotSet);
        params.SetNumLargeDigits(1);
    }

    CCParams<CryptoContextBGVRNS> params;
}; 

#define MAKE_BENCHMARK(name, K, D, L) BENCHMARK_F(ServerWrite, name)(benchmark::State& s) { \
    for (auto _ : s) { server::TestServerWrite<DCRTPoly, K, D, L>(params); } \
}

MAKE_BENCHMARK(N2,  3, 3, 1)
MAKE_BENCHMARK(N32, 3, 3, 5)
// MAKE_BENCHMARK(N64, 3, 3, 6, CreateParams(3))
// MAKE_BENCHMARK(N128, 3, 3, 7, CreateParams(3))

BENCHMARK_MAIN();
