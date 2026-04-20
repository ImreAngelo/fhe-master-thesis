#include <chrono>
#include <iostream>
#include <iomanip>

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
        explicit Timer(const char* label)
            : label_(label), start_(Clock::now()) {}

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
        const char*              label_;
        Clock::time_point        start_;
    };

}