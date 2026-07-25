#include "spar/params.h"
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <toml++/toml.hpp>

namespace spar::params {

namespace {

/// @brief Location of params.toml: $SPAR_PARAMS_FILE, else the absolute path
///        baked in by CMake.
std::string FilePath() {
    if (const char* path = std::getenv("SPAR_PARAMS_FILE")) return path;
    return SPAR_PARAMS_FILE;
}

const toml::table& Parsed() {
    // Magic static: parsed once, thread-safe.
    static const toml::table table = [] {
        const std::string path = FilePath();
        try {
            return toml::parse_file(path);
        } catch (const toml::parse_error& e) {
            std::ostringstream msg;
            msg << "spar::params: cannot parse '" << path << "': " << e.description() << " at line " << e.source().begin.line << ", column "
                << e.source().begin.column << " (set SPAR_PARAMS_FILE to override the location)";
            throw std::runtime_error(msg.str());
        }
    }();
    return table;
}

/// @brief Names of every set, for error messages.
std::string AvailableNames() {
    std::string names;
    for (const auto& [key, value] : Parsed()) {
        if (!value.is_table()) continue;
        if (!names.empty()) names += ", ";
        names += std::string(key.str());
    }
    return names.empty() ? "(none)" : names;
}

[[noreturn]] void MissingKey(const std::string& set, const std::string& key) {
    throw std::runtime_error("spar::params: set '" + set + "' in " + FilePath() + " is missing key '" + key + "'");
}

template <typename T>
T Require(const toml::table& section, const std::string& set, const std::string& key) {
    const auto value = section[key].value<T>();
    if (!value) MissingKey(set, key);
    return *value;
}

Scheme ParseScheme(const std::string& set, const std::string& value) {
    if (value == "bv") return Scheme::BV;
    if (value == "hybrid") return Scheme::Hybrid;
    throw std::runtime_error("spar::params: set '" + set + "' has scheme = \"" + value + "\"; expected \"bv\" or \"hybrid\"");
}

Set ReadSet(const std::string& name, const toml::table& section) {
    Set set;
    set.name = name;
    set.plaintextModulus = Require<int64_t>(section, name, "plaintext_modulus");
    set.ringDim = Require<int64_t>(section, name, "ring_dim");
    set.limbs = Require<int64_t>(section, name, "limbs");
    set.firstModSize = Require<int64_t>(section, name, "first_mod_size");
    set.scalingModSize = Require<int64_t>(section, name, "scaling_mod_size");
    set.standardDeviation = static_cast<float>(Require<double>(section, name, "standard_deviation"));
    set.ell = Require<int64_t>(section, name, "ell");
    set.scheme = ParseScheme(name, Require<std::string>(section, name, "scheme"));
    return set;
}

/// @brief Announce the active set once, so every run records what it used.
void AnnounceOnce(const Set& set) {
    static bool announced = false;
    if (announced) return;
    announced = true;
    std::cerr << "[spar::params] set=" << set.name << " N=" << set.ringDim << " t=" << set.plaintextModulus << " limbs=" << set.limbs
              << " |Q|=" << set.LogQ() << " ell=" << set.ell << " scheme=" << (set.scheme == Scheme::Hybrid ? "hybrid" : "bv") << " ("
              << FilePath() << ")\n";
}

}  // namespace

uint32_t Set::Depth(const Mode mode) const {
    // One limb is always the top level. NOISE_FLOODING_MULTIPARTY additionally
    // inserts NUM_MODULI_MULTIPARTY primes into Q, which OpenFHE spends before
    // any multiplicative level is available. Taken from OpenFHE's own constant so
    // the two stay in sync if upstream changes it.
    const uint32_t reserved = 1 + (mode == Mode::MultiParty ? static_cast<uint32_t>(lbcrypto::NoiseFlooding::NUM_MODULI_MULTIPARTY) : 0u);

    if (limbs <= reserved)
        throw std::runtime_error("spar::params: set '" + name + "' has limbs = " + std::to_string(limbs) + " but this mode reserves " +
                                 std::to_string(reserved) + "; no usable multiplicative level remains");

    return limbs - reserved;
}

Set Resolve(const std::string& name) {
    const auto* section = Parsed()[name].as_table();
    if (!section)
        throw std::runtime_error("spar::params: no set named '" + name + "' in " + FilePath() + "; available: " + AvailableNames());

    const Set set = ReadSet(name, *section);
    AnnounceOnce(set);
    return set;
}

Set Resolve() {
    const char* name = std::getenv("SPAR_PARAMS");
    return Resolve(name ? name : "standard");
}

BGVParams Make(const Set& set, const Mode mode) {
    BGVParams params;
    params.SetPlaintextModulus(set.plaintextModulus);
    params.SetRingDim(set.ringDim);
    params.SetMultiplicativeDepth(set.Depth(mode));
    params.SetFirstModSize(set.firstModSize);
    params.SetScalingModSize(set.scalingModSize);
    params.SetStandardDeviation(set.standardDeviation);

    // Invariants — deliberately not configurable in params.toml.
    params.SetSecurityLevel(lbcrypto::HEStd_NotSet);    // certified via scripts/estimate-security-param.py
    params.SetScalingTechnique(lbcrypto::FIXEDMANUAL);  // the RGSW gadget assumes no automatic rescaling
    params.SetKeySwitchTechnique(lbcrypto::HYBRID);     // GHS
    params.SetNumLargeDigits(1);

    // Inseparable from Depth(Mode::MultiParty): OpenFHE only inserts the two
    // flooding primes when this mode is set.
    if (mode == Mode::MultiParty) params.SetMultipartyMode(lbcrypto::NOISE_FLOODING_MULTIPARTY);

    return params;
}

core::ExtendedContext MakeContext(const Set& set, const Scheme scheme, const Mode mode) {
    const auto params = Make(set, mode);

    auto cc = (scheme == Scheme::Hybrid) ? core::GenContextHybrid(params) : core::GenContextBV(params, set.ell);

    cc->Enable(lbcrypto::PKE);
    cc->Enable(lbcrypto::KEYSWITCH);
    cc->Enable(lbcrypto::LEVELEDSHE);  // server::Write uses EvalAdd
    if (mode == Mode::MultiParty) cc->Enable(lbcrypto::MULTIPARTY);

    return cc;
}

core::ExtendedContext MakeContext(const Set& set, const Mode mode) {
    return MakeContext(set, set.scheme, mode);
}

}  // namespace spar::params
