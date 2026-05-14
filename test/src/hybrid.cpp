#include "openfhe.h"
#include "core/include/context.h"

using namespace lbcrypto;
using namespace Context;

inline void run() {
    auto params = params::Small<CryptoContextBGVRNS>();
    params.SetNumLargeDigits(2); // P ~= Q^{1/d}

    auto cc = GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keys = cc->KeyGen();


}

TEST(RGSW, HYBRID) { run(); };