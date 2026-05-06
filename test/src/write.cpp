#include "openfhe.h"
#include "core/context.h"
#include "server/server.h"

using namespace lbcrypto;

inline CCParams<CryptoContextRGSWBGV> CreateParams(uint32_t depth, uint32_t ringDimLog = 14) {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(depth);
    params.SetPlaintextModulus(8);
    params.SetRingDim(1 << ringDimLog);
    // params.SetScalingTechnique(FIXEDMANUAL);

    params.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    return params;
}

// TEST(Server, Write_1s) { server::TestServerWrite<DCRTPoly, 1, 1, 1>(CreateParams(2)); }
// TEST(Server, Write_2s) { server::TestServerWrite<DCRTPoly, 2, 2, 1>(CreateParams(3)); }

// TEST(Server, Write_1k2d) { server::TestServerWrite<DCRTPoly, 1, 2, 1>(CreateParams(8)); }
// TEST(Server, Write_2k1d) { server::TestServerWrite<DCRTPoly, 1, 2, 1>(CreateParams(8)); }

// Main tests
TEST(ServerWrite, N2)  { server::TestServerWrite<DCRTPoly, 3, 3, 1>(CreateParams(1)); }
// TEST(ServerWrite, N4)  { server::TestServerWrite<DCRTPoly, 3, 3, 2>(CreateParams(3)); }
// TEST(ServerWrite, N8)  { server::TestServerWrite<DCRTPoly, 3, 3, 3>(CreateParams(3)); }
// TEST(ServerWrite, N16) { server::TestServerWrite<DCRTPoly, 3, 3, 4>(CreateParams(3)); }
// TEST(Server, Write_N4)  { server::TestServerWrite<DCRTPoly, 3, 3, 2>(CreateParams(3)); }
// TEST(Server, Write_N8)  { server::TestServerWrite<DCRTPoly, 3, 3, 3>(CreateParams(3)); }
// TEST(Server, Write_N16) { server::TestServerWrite<DCRTPoly, 3, 3, 4>(CreateParams(3)); }
// TEST(Server, Write_N32) { server::TestServerWrite<DCRTPoly, 3, 3, 5>(CreateParams(3)); }
