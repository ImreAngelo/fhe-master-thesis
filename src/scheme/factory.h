#pragma once
#include "openfhe.h"

/// @brief Factory for constructing and registering ExtendedContext instances similar to creating OpenFHE CryptoContexts
namespace spar::factory {

// CryptoContextFactory::AddContext is protected to push users through GenCryptoContext(). 
// For our extended impls we construct the context ourselves, so we need direct access.
template <typename Element>
struct FactoryRegistrar : protected lbcrypto::CryptoContextFactory<Element> {
    static void Add(lbcrypto::CryptoContext<Element> cc) {
        lbcrypto::CryptoContextFactory<Element>::AddContext(std::move(cc));
    }
};

} // namespace spar::factory