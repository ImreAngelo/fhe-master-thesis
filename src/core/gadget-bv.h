#include "openfhe.h"



/**
 * @brief BV-RNS gadget decomposition in EVALUATION format
 */
namespace bvrns {
    using namespace lbcrypto;

    namespace ntt {
        /// @brief Stays in evaluation format, but cannot use centered representation so it is much faster but also much noisier! 
        std::vector<DCRTPoly> UnsignedDigitDecompose(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly& input);
    }

    /// @brief Slower COEFFICIENT format, but less noise with centered representation
    std::vector<DCRTPoly> SignedDigitDecompose(const std::shared_ptr<CryptoParametersRNS> params, const DCRTPoly& input);

    /// @brief Gadget-dual of SignedDigitDecompose

} // namespace bvrns