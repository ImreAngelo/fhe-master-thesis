#pragma once

namespace spar::server {

template <typename T, uint32_t K = 3>
using Matrix = std::vector<std::array<T, K>>;

}