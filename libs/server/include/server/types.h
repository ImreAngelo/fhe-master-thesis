#pragma once

#include "core/types.h"

namespace spar::server {

template<uint32_t K = 3>
using Matrix = std::vector<std::array<core::RGSW, K>>;

}