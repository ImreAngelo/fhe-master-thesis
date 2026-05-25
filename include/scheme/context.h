#pragma once

#include "openfhe.h"
#include "types.h"


namespace spar {

class IExtendedCryptoContextImpl : public lbcrypto::CryptoContextImpl<Poly> {
    using Base = lbcrypto::CryptoContextImpl<Poly>;

public:
    virtual RGSW EncryptRGSW(const PublicKey&, const Plaintext&, const bool noisy = true) const = 0;
    virtual RLWE EvalExternalProduct(const RLWE&, const RGSW&) const = 0;
    virtual RGSW EvalInternalProduct(const RGSW&, const RGSW&) const = 0;

protected:
    explicit IExtendedCryptoContextImpl(const Base& cc) : Base(cc) {}
};

using ExtendedCryptoContext = std::shared_ptr<IExtendedCryptoContextImpl>;

}  // namespace spar