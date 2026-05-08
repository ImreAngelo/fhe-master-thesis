#pragma once

#include "scheme/bgvrns/gen-cryptocontext-bgvrns-params.h"
#include "openfhe.h"


/**
 * @brief Parameters for ExtendedCryptoContext (not used in RNS)
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