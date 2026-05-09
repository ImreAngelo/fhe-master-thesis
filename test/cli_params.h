#pragma once

// Shared CLI flag parsing for tunable test binaries. Every test that opts into
// CUSTOM_MAIN includes this header, defines its own main(), and reads the
// globals in the test body. Tests that don't care about a particular slot
// just leave it untouched — defaults stay hardcoded inside the test.

#include "openfhe.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace test_cli {

inline std::optional<uint32_t>                  g_mult_depth;
inline std::optional<uint32_t>                  g_plaintext_modulus;
inline std::optional<uint32_t>                  g_ring_dim;
inline std::optional<uint32_t>                  g_gadget_base;
inline std::optional<uint32_t>                  g_gadget_decomposition;
inline std::optional<lbcrypto::ScalingTechnique> g_scaling_technique;

inline lbcrypto::ScalingTechnique parse_scaling(std::string_view name) {
    if (name == "FIXEDAUTO")       return lbcrypto::FIXEDAUTO;
    if (name == "FIXEDMANUAL")     return lbcrypto::FIXEDMANUAL;
    if (name == "FLEXIBLEAUTO")    return lbcrypto::FLEXIBLEAUTO;
    if (name == "FLEXIBLEAUTOEXT") return lbcrypto::FLEXIBLEAUTOEXT;
    std::cerr << "unknown scaling_technique: " << name << "\n";
    std::exit(2);
}

// Walks the post-InitGoogleTest argv and fills the globals above. Returns 0 on
// success or a non-zero exit code that main() should propagate.
inline int parse_args(int argc, char** argv) {
    auto uint_arg = [](std::string_view v, std::optional<uint32_t>& slot, std::string_view name) {
        try {
            slot = static_cast<uint32_t>(std::stoul(std::string(v)));
        } catch (const std::exception&) {
            std::cerr << "invalid value for --" << name << ": " << v << "\n";
            std::exit(2);
        }
    };

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        const auto eq = arg.find('=');
        if (arg.substr(0, 2) != "--" || eq == std::string_view::npos) {
            std::cerr << "unrecognised argument: " << arg << "\n";
            return 2;
        }
        const auto name  = arg.substr(2, eq - 2);
        const auto value = arg.substr(eq + 1);

        if      (name == "mult_depth")           uint_arg(value, g_mult_depth,           name);
        else if (name == "plaintext_modulus")    uint_arg(value, g_plaintext_modulus,    name);
        else if (name == "ring_dim")             uint_arg(value, g_ring_dim,             name);
        else if (name == "gadget_base")          uint_arg(value, g_gadget_base,          name);
        else if (name == "gadget_decomposition") uint_arg(value, g_gadget_decomposition, name);
        else if (name == "scaling_technique")    g_scaling_technique = parse_scaling(value);
        else {
            std::cerr << "unknown flag --" << name << "\n";
            return 2;
        }
    }
    return 0;
}

}  // namespace test_cli
