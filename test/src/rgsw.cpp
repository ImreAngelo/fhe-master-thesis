#include "scheme/context-bv.h"


TEST(RGSW, Classes) {
    using namespace spar;

    auto params = params::Small<CryptoContextBV>();
    params.SetEll(1);

    const auto cc = lbcrypto::GenCryptoContext(params);
};
