// TODO: Clean up everything
#define ASSERT_EQ(a, b)

#include <benchmark/benchmark.h>
#include "openfhe.h"
#include "server/server.h"

using namespace lbcrypto;

inline CCParams<CryptoContextRGSWBGV> CreateParams(uint32_t depth) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(depth);
    params.SetPlaintextModulus(8);
    params.SetRingDim(2048);
    // params.SetScalingTechnique(FIXEDAUTO);
    // params.SetNumLargeDigits(3);

    params.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    return params;
}

class ServerWrite : public benchmark::Fixture {
public:
    void SetUp(const benchmark::State&) override {}
}; 

#define MAKE_BENCHMARK(name, K, D, L, params) BENCHMARK_F(ServerWrite, name)(benchmark::State& s) { \
    auto p = params; \
    for (auto _ : s) { server::TestServerWrite<DCRTPoly, K, D, L>(p); } \
}

// TODO: Only benchmark with K = D = 3?
MAKE_BENCHMARK(mvp, 1, 1, 1, CreateParams(3))
MAKE_BENCHMARK(N2, 3, 3, 1, CreateParams(3))
MAKE_BENCHMARK(N4, 3, 3, 2, CreateParams(3))
MAKE_BENCHMARK(N8, 3, 3, 3, CreateParams(3))
MAKE_BENCHMARK(N16, 3, 3, 4, CreateParams(3))
MAKE_BENCHMARK(N32, 3, 3, 5, CreateParams(3))
MAKE_BENCHMARK(N64, 3, 3, 6, CreateParams(3))
MAKE_BENCHMARK(N128, 3, 3, 7, CreateParams(3))

BENCHMARK_MAIN();
