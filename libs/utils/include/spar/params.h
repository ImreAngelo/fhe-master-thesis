#pragma once

#include "core/context.h"
#include "openfhe.h"
#include <cstdint>
#include <string>

/**
 * @file params.h
 * @brief Crypto parameters, loaded at runtime from params.toml at the repo root.
 *
 * The file is located via $SPAR_PARAMS_FILE, else the absolute path baked in at
 * configure time. The active set is $SPAR_PARAMS, else "standard". Both are
 * runtime lookups, so changing a parameter never requires a rebuild.
 */
namespace spar::params {

using BGVParams = lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS>;

/// @brief Gadget / key-switching variant.
enum class Scheme { BV, Hybrid };

/// @brief Single-party vs OpenFHE threshold FHE. Decides how many RNS limbs are
///        spent on noise flooding, and therefore the multiplicative depth.
enum class Mode { SingleParty, MultiParty };

/// @brief One parameter set, exactly as read from params.toml.
///        Returned by value: copy it and mutate one field to express a
///        deliberate, commented delta at a call site.
struct Set {
    std::string name;

    PlaintextModulus plaintextModulus;  ///< t (OpenFHE global typedef, see core/utils/inttypes.h)
    uint32_t ringDim;                   ///< N
    uint32_t limbs;                     ///< total RNS limbs in Q, both modes
    uint32_t firstModSize;              ///< bits in q_0
    uint32_t scalingModSize;            ///< bits in q_i, i > 0
    float standardDeviation;            ///< absolute sigma
    uint32_t ell;                       ///< BV gadget digits; ignored by Hybrid
    Scheme scheme;                      ///< default scheme for this set

    /// @brief |Q| in bits. Identical derivation to the estimator's.
    uint32_t LogQ() const { return firstModSize + (limbs - 1) * scalingModSize; }

    /// @brief OpenFHE multiplicativeDepth for @p mode.
    ///        Throws if limbs leaves no usable level.
    uint32_t Depth(Mode mode) const;
};

/// @brief The active set: $SPAR_PARAMS, else "standard".
Set Resolve();

/// @brief A named set. Throws std::runtime_error listing the available names.
Set Resolve(const std::string& name);

/// @brief CCParams with the pinned invariants and the mode-derived depth applied.
BGVParams Make(const Set& set, Mode mode = Mode::SingleParty);

/// @brief Build the context and Enable() the standard feature set. Dispatches on
///        set.scheme.
core::ExtendedContext MakeContext(const Set& set, Mode mode = Mode::SingleParty);

/// @brief As above, overriding the set's declared scheme.
core::ExtendedContext MakeContext(const Set& set, Scheme scheme, Mode mode = Mode::SingleParty);

}  // namespace spar::params
