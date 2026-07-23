#pragma once

#include "pke/cryptocontext.h"
#include "types.h"


namespace core {

class IExtendedContext : public lbcrypto::CryptoContextImpl<Poly> {
    using Base = lbcrypto::CryptoContextImpl<Poly>;

   public:
    /// @brief Publish extended (QP) key material. Required by the hybrid scheme
    ///        (call once after KeyGen); a no-op for schemes that don't need it.
    virtual void SetExtendedKey(const lbcrypto::KeyPair<Poly>&) {}

    /// @brief Create a public key (noiseless RGSW)
    virtual RGSW MakePublicRGSW(const PublicKey&, const Plaintext&) const = 0;


    /// @brief Encrypt an RGSW ciphertext of message
    virtual RGSW EncryptRGSW(const PublicKey&, const Plaintext&) const = 0;

    /// @brief External product
    virtual RLWE EvalExternalProduct(const RLWE&, const RGSW&) const = 0;

    /// @brief Internal product
    virtual RGSW EvalInternalProduct(const RGSW&, const RGSW&) const = 0;


    /// @brief Add two RGSW ciphertexts
    virtual RGSW EvalAddRGSW(const RGSW&, const RGSW&) const = 0;

    /// @brief Subtract an RGSW ciphertext from another (lhs - rhs)
    virtual RGSW EvalSubRGSW(const RGSW&, const RGSW&) const = 0;

    /// @brief Multiply an RGSW ciphertext by a plaintext
    virtual RGSW EvalMultRGSW(const RGSW&, const Plaintext&) const = 0;

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

}  // namespace core