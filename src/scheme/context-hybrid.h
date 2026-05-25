#pragma once

#include "scheme/context.h"


namespace spar {

class ExtendedContextHybridImpl final : public IExtendedContext {
public:
    explicit ExtendedContextHybridImpl(const lbcrypto::CryptoContextImpl<Poly>& base) : IExtendedContext(base) {};

    RGSW EncryptRGSW(const PublicKey& pk, const Plaintext& pt, const bool noisy = true) const override;
    RLWE EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const override;
    RGSW EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const override;
};

using ExtendedContextHybrid = std::shared_ptr<ExtendedContextHybridImpl>;

} // namespace spar