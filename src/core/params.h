#pragma once

#include "scheme/bgvrns/gen-cryptocontext-bgvrns-params.h"
#include "openfhe.h"


/**
 * @file params.h
 * @brief This file defines the parameters required for generating an ExtendedCryptoContext.
 */
namespace lbcrypto {

class CryptoContextRGSWBGV;

/**
 * @brief Contains parameters for using RGSW with BGV-rns, as required by HomExpand and HomPlacing.
 */
template <>
class CCParams<CryptoContextRGSWBGV> : public CCParams<CryptoContextBGVRNS> {
public:
    CCParams() : CCParams<CryptoContextBGVRNS>() {}
    CCParams(const CCParams& obj) = default;
    CCParams(CCParams&& obj)      = default;
    ~CCParams()                   = default;
    
    // ----- RGSW-specific getters -----
    uint32_t GetGadgetBase() const { return gadgetBase; }
    uint32_t GetGadgetDecomposition() const { return gadgetDecomposition; }
    
    // ----- RGSW-specific setters -----
    void SetGadgetBase(uint32_t gadgetBase) { this->gadgetBase = gadgetBase; }
    void SetGadgetDecomposition(uint32_t gadgetDecomposition) { this->gadgetDecomposition = gadgetDecomposition; }
    
protected:
    uint32_t gadgetBase   = 2;          // B: gadget base (must be a power of 2)
    uint32_t gadgetDecomposition = 8;   // ℓ: levels
};

}  // namespace lbcrypto