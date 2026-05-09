#include "openfhe.h"
#include "core/context.h"
#include "server/server.h"

using namespace lbcrypto;

inline CCParams<CryptoContextBGVRNS> CreateParams(uint32_t depth, uint32_t ringDimLog = 11) {
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(1);
    params.SetPlaintextModulus(8);
    params.SetRingDim(1 << ringDimLog);
    params.SetScalingTechnique(FIXEDMANUAL);

    params.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    return params;
}

// Main tests
// TEST(ServerWrite, N2)  { server::TestServerWrite<DCRTPoly, 3, 3, 1>(CreateParams(1)); }
// TEST(ServerWrite, N4)  { server::TestServerWrite<DCRTPoly, 3, 3, 2>(CreateParams(3)); }
// TEST(ServerWrite, N8)  { server::TestServerWrite<DCRTPoly, 3, 3, 3>(CreateParams(3)); }
// TEST(ServerWrite, N16) { server::TestServerWrite<DCRTPoly, 3, 3, 4>(CreateParams(3)); }
// TEST(Server, Write_N4)  { server::TestServerWrite<DCRTPoly, 3, 3, 2>(CreateParams(3)); }
// TEST(Server, Write_N8)  { server::TestServerWrite<DCRTPoly, 3, 3, 3>(CreateParams(3)); }
// TEST(Server, Write_N16) { server::TestServerWrite<DCRTPoly, 3, 3, 4>(CreateParams(3)); }
// TEST(Server, Write_N32) { server::TestServerWrite<DCRTPoly, 3, 3, 5>(CreateParams(3)); }
