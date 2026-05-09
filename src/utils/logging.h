#if defined(DEBUG_LOGGING)
/// Print only in debug mode
#define DEBUG_PRINT(text) std::cout << text << std::endl
#else
/// Enable printing by defining a DEBUG_LOGGING macro
#define DEBUG_PRINT(text)
#endif