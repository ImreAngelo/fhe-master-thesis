#pragma once

#include "openfhe.h"
#include "scheme/bgvrns/gen-cryptocontext-bgvrns-internal.h"
#include "scheme/bgvrns/bgvrns-scheme.h"
#include "scheme/bgvrns/bgvrns-cryptoparameters.h"
#include "scheme/gen-cryptocontext-params-validation.h"

#include "params.h"

// CryptoContextRGSWBGV must live in lbcrypto so that the template deduction
// inside GenCryptoContext<T>(CCParams<T>) resolves to the specialisation
// CCParams<CryptoContextRGSWBGV> defined in params.h.
namespace lbcrypto {

template <typename Element>
class CryptoContextFactory;

// Generator class for a BGV-RNS context augmented with RGSW gadget parameters.
//
// Mirrors the structure of CryptoContextBGVRNS so that it can be used with the
// standard OpenFHE entry point:
//
//   CCParams<CryptoContextRGSWBGV> params;
//   params.SetPlaintextModulus(65537);
//   params.SetRingDim(2048);
//   params.SetMultiplicativeDepth(3);
//   params.SetGadgetBase(2);
//   params.SetGadgetDigits(27);
//   auto cc = GenCryptoContext(params);  // returns CryptoContext<DCRTPoly>
//
// The returned context is a standard BGV CryptoContext. The RGSW parameters
// (gadgetBase, gadgetDigits) are validated here and then used separately to
// build RGSWParams when needed.
class CryptoContextRGSWBGV {
    using Element = DCRTPoly;

public:
    // Required by GenCryptoContext() in gen-cryptocontext.h
    using ContextType               = CryptoContext<Element>;
    // Required by genCryptoContextBGVRNSInternal
    using Factory                   = CryptoContextFactory<Element>;
    using PublicKeyEncryptionScheme = SchemeBGVRNS;
    using CryptoParams              = CryptoParametersBGVRNS;

    static CryptoContext<Element> genCryptoContext(const CCParams<CryptoContextRGSWBGV>& parameters) {
        if (parameters.GetGadgetBase() == 0 || (parameters.GetGadgetBase() & (parameters.GetGadgetBase() - 1)) != 0)
            OPENFHE_THROW("CryptoContextRGSWBGV: gadgetBase must be a nonzero power of 2");

        validateParametersForCryptocontext(parameters);

        // genCryptoContextBGVRNSInternal is templated on the generator type and reads all parameters 
        // through the CCParams<> interface, which CCParams<CryptoContextRGSWBGV> satisfies via inheritance 
        // from CCParams<CryptoContextBGVRNS>.
        return genCryptoContextBGVRNSInternal<CryptoContextRGSWBGV, Element>(parameters);
    }
};

}  // namespace lbcrypto

namespace core {
using namespace lbcrypto;
}  // namespace core
