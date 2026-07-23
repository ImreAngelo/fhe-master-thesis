#pragma once

#include "core/context.h"
#include "core/types.h"
#include <stdexcept>

namespace spar::client {

using core::ExtendedContext;
using core::RLWE;

inline RLWE Encrypt(const ExtendedContext& cc, const std::vector<RLWE>& cts, const uint32_t n) {
    throw new std::logic_error("Not implemented");
};

inline std::vector<RLWE> decrypt() {
    throw new std::logic_error("Not implemented");
};

}  // namespace spar::client