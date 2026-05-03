#pragma once

#include <chrono>
#include <iostream>
#include <iomanip>
#include <string>


namespace utils {
    using Clock = std::chrono::high_resolution_clock;
    using Ms    = std::chrono::duration<double, std::milli>;

    /**
     * @brief RAII timer. Starts on construction, prints elapsed time on destruction.
     * { Timer t("label"); foo(); }
     *
     * @todo Include timings in plot-friendly format
     */
    struct Timer {
        explicit Timer(std::string && label)
            : m_label(std::move(label)), m_start(Clock::now()) {}

        ~Timer() {
            double ms = std::chrono::duration_cast<Ms>(Clock::now() - m_start).count();
            std::cout << "  [timing] " << m_label << ": "
                    << std::fixed << std::setprecision(2) << ms << " ms\n";

            // TODO: Log to file and only print to console if DEBUG_LOGGING is defined
        }

        /// @brief Call this to get an intermediate reading without stopping the timer.
        double elapsed_ms() const {
            return std::chrono::duration_cast<Ms>(Clock::now() - m_start).count();
        }

    private:
        std::string              m_label;
        Clock::time_point        m_start;
    };
}

#define CONCAT(a, b) a ## b
#if defined(DEBUG_TIMING)
/// Macro for creating an RAII timer
#define DEBUG_TIMER(label) utils::Timer CONCAT(t,__COUNTER__)(label)
#else
/// Enable timer by defining a DEBUG_TIMING macro
#define DEBUG_TIMER(label) 
#endif

#if defined(DEBUG_LOGGING)
/// Print only in debug mode
#define DEBUG_PRINT(text) std::cout << text << std::endl
#else
/// Enable printing by defining a DEBUG_LOGGING macro
#define DEBUG_PRINT(text)
#endif