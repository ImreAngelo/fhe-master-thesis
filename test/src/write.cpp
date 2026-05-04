// TODO: This should be handled by common.h!!!!!
#define DEBUG_TIMING
#define DEBUG_LOGGING
#include "utils/timer.h"

#include "openfhe.h"
#include "core/context.h"
#include "server/server.h"

using namespace lbcrypto;

inline CCParams<CryptoContextRGSWBGV> CreateParams(uint32_t depth, uint32_t ringDimLog = 14) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(depth);
    params.SetPlaintextModulus(65537);
    params.SetRingDim(1 << ringDimLog);
    params.SetScalingTechnique(FIXEDAUTO);

    params.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    return params;
}

TEST(Server, Write_1s) { server::TestServerWrite<DCRTPoly, 1, 1, 1>(CreateParams(3)); }
TEST(Server, Write_2s) { server::TestServerWrite<DCRTPoly, 2, 2, 1>(CreateParams(5)); }
// TEST(ServerWrite, Params_K2)  { TestServerWrite<DCRTPoly, 2, 1, 1>(CreateParams(8)); }
// TEST(ServerWrite, Params_D2)  { TestServerWrite<DCRTPoly, 1, 2, 1>(CreateParams(8)); }
// TEST(ServerWrite, Params_A2)  { TestServerWrite<DCRTPoly, 2, 2, 1>(CreateParams(12)); }

// TEST(Server, Write_2s)  { TestServerWrite<DCRTPoly, 2, 2, 1>(CreateParams(12)); }

// GOAL: Pass this test!
TEST(Server, Write_N2)  { server::TestServerWrite<DCRTPoly, 3, 3, 1>(CreateParams(12)); }
