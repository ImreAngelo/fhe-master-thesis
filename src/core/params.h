#pragma once

#include "scheme/bgvrns/gen-cryptocontext-bgvrns-params.h"
#include "openfhe.h"


/**
 * @file params.h
 * @brief Parameters for ExtendedCryptoContext (BGV-RNS + RGSW).
 *
 * The RGSW gadget structure now reuses the hybrid keyswitch RNS digit
 * decomposition (dnum digits of α = numPerPartQ RNS limbs each). Set dnum
 * via the inherited CCParams<CryptoContextBGVRNS>::SetNumLargeDigits.
 */
namespace lbcrypto {

class CryptoContextRGSWBGV;

/**
 * @brief Marker subclass used by GenExtendedCryptoContext.
 */
template <>
class CCParams<CryptoContextRGSWBGV> : public CCParams<CryptoContextBGVRNS> {
public:
    CCParams() : CCParams<CryptoContextBGVRNS>() {}
    CCParams(const CCParams& obj) = default;
    CCParams(CCParams&& obj)      = default;
    ~CCParams()                   = default;
};

}  // namespace lbcrypto
