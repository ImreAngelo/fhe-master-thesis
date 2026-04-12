/**
 * @brief returns 2^n
 * @param n the exponent
 * @return 2^n
 */
template <typename T>
constexpr inline T Log2(T n) {
    T k = 0;
    while ((T(1) << k) < n) {
        k++;
    }
    return k;
}
