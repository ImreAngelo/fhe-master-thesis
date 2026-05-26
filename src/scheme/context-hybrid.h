#pragma once

#include "scheme/context.h"


namespace spar {

class ExtendedContextHybridImpl final : public IExtendedContext {
public:
    explicit ExtendedContextHybridImpl(const lbcrypto::CryptoContextImpl<Poly>& base);

    RGSW EncryptRGSW(const PublicKey& pk, const Plaintext& pt, const bool noisy = true) const override;
    RLWE EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const override;
    RGSW EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const override;

    RGSW EvalAddRGSW(const RGSW& lhs, const RGSW& rhs) const;
    RGSW EvalSubRGSW(const RGSW& lhs, const RGSW& rhs) const;
    RGSW EvalMultRGSW(const RGSW& rgsw, const Plaintext& pt) const;

private:
    /// @brief Thin wrapper around OpenFHE's ApproxModDown (QP -> Q)
    Poly ApproxModDown(const Poly&) const;

    /// @brief Scale Q -> QP
    Poly Power(const Poly&) const;

    /// @brief Decompose QP -> Q
    Poly Decompose(const Poly&) const;

private:
    const std::shared_ptr<lbcrypto::CryptoParametersRNS> m_params;
    const std::vector<std::vector<NativeInteger>> m_qHatModP; // TODO: Flatten
    const std::vector<NativeInteger> m_qHatInv;
};

using ExtendedContextHybrid = std::shared_ptr<ExtendedContextHybridImpl>;

} // namespace spar