#include "context-hybrid.h"
#include "factory.h"

namespace spar {

RGSW ExtendedContextHybridImpl::EncryptRGSW(const PublicKey& pk, const Plaintext& pt, const bool noisy) const {
    return RGSW();
}

RLWE ExtendedContextHybridImpl::EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const {
    return RLWE();
}

RGSW ExtendedContextHybridImpl::EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const {
    return RGSW();
}

//-------------------------//
// OpenFHE-Context Factory //
//-------------------------//

ExtendedContext GenContextHybrid(const lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS>& parameters) {
    auto baseCC = lbcrypto::GenCryptoContext(parameters);
    auto ext = std::make_shared<ExtendedContextHybridImpl>(*baseCC);
    factory::FactoryRegistrar<Poly>::Add(ext);
    return ext;
}

} // namespace spar