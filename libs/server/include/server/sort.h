#pragma once

#include "openfhe.h"

namespace spar::server {

/// @brief After server::Write, each bucket should be sorted before decryption
inline void SortBucket() {};

}  // namespace spar::server