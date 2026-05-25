#include "context-hybrid.h"

using namespace spar;

RGSW spar::ExtendedContextHybridImpl::EncryptRGSW(const PublicKey& pk, const Plaintext& pt, const bool noisy) const {
    return RGSW();
}

RLWE spar::ExtendedContextHybridImpl::EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const {
    return RLWE();
}

RGSW spar::ExtendedContextHybridImpl::EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const {
    return RGSW();
}
