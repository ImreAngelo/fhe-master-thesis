#pragma once

#include "core/context.h"


namespace core {

class ExtendedContextHybridImpl final : public IExtendedContext {
   public:
    explicit ExtendedContextHybridImpl(const lbcrypto::CryptoContextImpl<Poly>& base);

    /// @brief Build and store the QP public key (needs the secret key once, at setup)
    void SetExtendedKey(const lbcrypto::KeyPair<Poly>& keys) override;

    RGSW MakePublicRGSW(const PublicKey&, const Plaintext&) const override;
    RGSW EncryptRGSW(const PublicKey& pk, const Plaintext& pt) const override;
    RLWE EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const override;
    RGSW EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const override;

    RGSW EvalAddRGSW(const RGSW& lhs, const RGSW& rhs) const override;
    RGSW EvalSubRGSW(const RGSW& lhs, const RGSW& rhs) const override;
    RGSW EvalMultRGSW(const RGSW& rgsw, const Plaintext& pt) const override;

   private:
    /// @brief Exact multiply-by-P lift Q -> QP: represents P·x mod QP.
    ///        Identity: Power(x) ≡ P·Lift(x) (mod QP).
    Poly Power(const Poly&) const;

    /// @brief Unscaled lift Q -> QP (fast base extension): represents x + Q·u, small u.
    Poly Lift(const Poly&) const;

    /// @brief Fresh native-error RLWE encryption of zero at modulus QP, using m_pkQP.
    ///        The error is NOT scaled by P, which is what lets ApproxModDown suppress
    ///        the external-product cross-term by a factor P.
    std::vector<Poly> EncryptZeroQP() const;

   private:
    const std::shared_ptr<lbcrypto::CryptoParametersRNS> m_params;
    const std::vector<std::vector<NativeInteger>> m_qHatModP;  // TODO: Flatten
    const std::vector<NativeInteger> m_qHatInv;

    // QP public key (b = -a*s + t*e, a) with a uniform mod QP; set by SetExtendedKey.
    std::vector<Poly> m_pkQP;
};

using ExtendedContextHybrid = std::shared_ptr<ExtendedContextHybridImpl>;

}  // namespace core