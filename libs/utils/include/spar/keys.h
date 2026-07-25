#pragma once

#include "core/context.h"
#include "core/types.h"

/**
 * @file keys.h
 * @brief Key generation for an extended context.
 */
namespace spar::utils {

/// @brief KeyGen + publish the extended (QP) key material. SetExtendedKey is a
///        no-op for BV, so call sites never branch on the scheme.
inline lbcrypto::KeyPair<core::Poly> MakeKeys(const core::ExtendedContext& cc) {
    auto keys = cc->KeyGen();
    cc->SetExtendedKey(keys);
    return keys;
}

}  // namespace spar::utils
