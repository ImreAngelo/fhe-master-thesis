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
        explicit Timer(std::string label)
            : label_(std::move(label)), start_(Clock::now()) {}

        ~Timer() {
            double ms = std::chrono::duration_cast<Ms>(Clock::now() - start_).count();
            std::cout << "  [timing] " << label_ << ": "
                    << std::fixed << std::setprecision(2) << ms << " ms\n";
        }

        /// @brief Call this to get an intermediate reading without stopping the timer.
        double elapsed_ms() const {
            return std::chrono::duration_cast<Ms>(Clock::now() - start_).count();
        }

    private:
        std::string              label_;
        Clock::time_point        start_;
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