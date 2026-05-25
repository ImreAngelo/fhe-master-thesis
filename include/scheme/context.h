#pragma once

#include "openfhe.h"
#include "types.h"


namespace spar {

class IExtendedContext : public lbcrypto::CryptoContextImpl<Poly> {
    using Base = lbcrypto::CryptoContextImpl<Poly>;

public:
    /// @brief Encrypt an RGSW ciphertext of message
    virtual RGSW EncryptRGSW(const PublicKey&, const Plaintext&, const bool noisy = true) const = 0;
    virtual RLWE EvalExternalProduct(const RLWE&, const RGSW&) const = 0;
    virtual RGSW EvalInternalProduct(const RGSW&, const RGSW&) const = 0;

protected:
    explicit IExtendedContext(const Base& cc) : Base(cc) {}
};

using ExtendedContext = std::shared_ptr<IExtendedContext>;

/// @todo Allow other base schemes than BGV
// using BGVParams = lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS>;
// using BFVParams = lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS>;

// Create concrete contexts
ExtendedContext GenContextBV(const lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS>&, const uint32_t ell = 1);
ExtendedContext GenContextHybrid(const lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS>&);

}  // namespace spar