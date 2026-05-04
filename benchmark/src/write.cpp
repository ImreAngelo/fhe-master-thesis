// TODO: Clean up everything
#define ASSERT_EQ(a, b)

#include <benchmark/benchmark.h>
#include "openfhe.h"
#include "server/server.h"

using namespace lbcrypto;

inline CCParams<CryptoContextRGSWBGV> CreateParams(uint32_t depth, uint32_t ringDimLog = 14) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(depth);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(1 << ringDimLog);
    params.SetScalingTechnique(FIXEDAUTO);
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

// TODO: Only benchmark with K = D = 3
MAKE_BENCHMARK(all_1s, 1, 1, 1, CreateParams(5))
MAKE_BENCHMARK(all_2s, 2, 2, 1, CreateParams(12))

BENCHMARK_MAIN();
