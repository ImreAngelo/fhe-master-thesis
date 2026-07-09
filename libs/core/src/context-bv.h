#pragma once

#include "core/context.h"

namespace core {

class ExtendedContextBVImpl final : public IExtendedContext {
   public:
    explicit ExtendedContextBVImpl(const lbcrypto::CryptoContextImpl<Poly>&, uint32_t ell);

    RGSW MakePublicRGSW(const PublicKey& pk, const Plaintext& pt) const override;
    RGSW EncryptRGSW(const PublicKey& pk, const Plaintext& pt) const override;
    RLWE EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const override;
    RGSW EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const override;

    RGSW EvalAddRGSW(const RGSW& lhs, const RGSW& rhs) const override { throw new std::logic_error("Not implemented."); };
    RGSW EvalSubRGSW(const RGSW& lhs, const RGSW& rhs) const override { throw new std::logic_error("Not implemented."); };
    RGSW EvalMultRGSW(const RGSW& rgsw, const Plaintext& pt) const override { throw new std::logic_error("Not implemented."); };

   private:
    const uint32_t m_ell;
    const uint64_t m_logB;
    const uint64_t m_offset;
    const std::vector<NativeInteger> m_powers;

   private:
    /// @returns B^i mod q_j
    NativeInteger GetPower(const uint32_t i, const uint32_t j) const;

    /// @returns Signed digit decomposition of the input polynomial
    std::vector<Poly> Decompose(const Poly&) const;
};

using ExtendedContextBV = std::shared_ptr<ExtendedContextBVImpl>;

}  // namespace core