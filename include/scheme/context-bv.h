#pragma once

#include "context.h"


namespace spar {

class BVCryptoContextImpl final : public IExtendedCryptoContextImpl {
public:
    explicit BVCryptoContextImpl(const lbcrypto::CryptoContextImpl<Poly>&, uint32_t ell);

    RGSW EncryptRGSW(const PublicKey& pk, const Plaintext& pt, const bool noisy = true) const override;
    RLWE EvalExternalProduct(const RLWE& rlwe, const RGSW& rgsw) const override;
    RGSW EvalInternalProduct(const RGSW& lhs, const RGSW& rhs) const override;
    
private:
    const uint32_t m_ell;
    const uint64_t m_logB;
    const std::vector<NativeInteger> m_powers;

private:
    /// @returns B^i mod q_j
    NativeInteger GetPower(const uint32_t i, const uint32_t j) const;

    /// @returns Input polynomial scaled by B^i as (a, aB, ..., aB^{ell - 1})
    std::vector<Poly> PowersOfBase(const Poly&) const;

    /// @returns Signed digit decomposition of the input polynomial
    std::vector<Poly> Decompose(const Poly&) const;
};

using BVCryptoContext = std::shared_ptr<BVCryptoContextImpl>;

//-------------------------//
// OpenFHE-Context Factory //
//-------------------------//

/// @brief Tag class consumed by lbcrypto::GenCryptoContext<spar::CryptoContextBV>(params)
class CryptoContextBV {
public:
    using ContextType = BVCryptoContext;

    static BVCryptoContext genCryptoContext(const CCParams<CryptoContextBV>& parameters);
};

} // namespace spar


namespace lbcrypto {

template <>
class CCParams<spar::CryptoContextBV> : public CCParams<CryptoContextBGVRNS> {
    uint32_t m_ell = 1;

public:
    CCParams()                = default;
    CCParams(const CCParams&) = default;
    CCParams(CCParams&&)      = default;
    ~CCParams()               = default;

    void SetEll(uint32_t ell) { m_ell = ell; }
    uint32_t GetEll() const   { return m_ell; }
};

} // namespace lbcrypto
