#pragma once

#include "openfhe.h"
#include "scheme/bgvrns/gen-cryptocontext-bgvrns-params.h"


/**
 * @file params.h
 * @brief This file defines the parameters required for generating a CryptoContext.
 */

// C++ only permits specializing a template in the namespace where it was originally declared (or an enclosing one).
namespace lbcrypto {

class CryptoContextRGSWBGV;

/**
 * @brief Contains parameters for using RGSW with BGV-rns, as required by HomExpand and HomPlacing.
 */
template <>
class CCParams<CryptoContextRGSWBGV> : public CCParams<CryptoContextBGVRNS> {
    uint32_t gadgetBase   = 2;  // B: gadget base (must be a power of 2)
    uint32_t gadgetDigits = 8;  // ℓ: levels

public:
    CCParams() : CCParams<CryptoContextBGVRNS>() {}
    CCParams(const CCParams& obj) = default;
    CCParams(CCParams&& obj)      = default;
    ~CCParams()                   = default;

    // ----- RGSW-specific getters -----
    uint32_t GetGadgetBase() const { return gadgetBase; }
    uint32_t GetGadgetDigits() const { return gadgetDigits; }

    // ----- RGSW-specific setters -----
    void SetGadgetBase(uint32_t gadgetBase0) { gadgetBase = gadgetBase0; }
    void SetGadgetDigits(uint32_t gadgetDigits0) { gadgetDigits = gadgetDigits0; }
};

}  // namespace lbcrypto

// Bring lbcrypto symbols into core.
namespace core {
using namespace lbcrypto;
}  // namespace core
