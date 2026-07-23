#pragma once

#include <filesystem>
#include <fstream>
#include <string>

/**
 * @file record.h
 * @brief Streams measurements to a CSV file for plotting.
 *
 * Wrap a measurement loop in RECORD_START("results/foo.csv", "n,msb,noise") /
 * RECORD_END(), and call RECORD(a, b, c) once per row inside the block.
 * No-ops unless DEBUG_LOGGING is defined (DEBUG=1 make test-<name>).
 */
namespace core::utils {

inline std::ofstream& RecordStream() {
    static std::ofstream os;
    return os;
}

inline void RecordStart(const std::string& filename, const std::string& header) {
    auto& os = RecordStream();
    if (os.is_open()) os.close();

    const std::filesystem::path path(filename);
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());

    os.open(path, std::ios::trunc);
    os << header << '\n';
}

template <typename First, typename... Rest>
void RecordRow(const First& first, const Rest&... rest) {
    auto& os = RecordStream();
    if (!os.is_open()) return;
    os << first;
    ((os << ',' << rest), ...);
    os << '\n';
}

inline void RecordEnd() {
    RecordStream().close();
}

}  // namespace core::utils

#if defined(DEBUG_LOGGING)
#define RECORD_START(filename, header) core::utils::RecordStart((filename), (header))
#define RECORD(...) core::utils::RecordRow(__VA_ARGS__)
#define RECORD_END() core::utils::RecordEnd()
#else
/// Enable recording by defining a DEBUG_LOGGING macro
#define RECORD_START(filename, header) \
    do {                               \
    } while (0);
#define RECORD(...) \
    do {            \
    } while (0);
#define RECORD_END() \
    do {             \
    } while (0);
#endif
