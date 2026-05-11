#include "openfhe.h"

using namespace lbcrypto;

/**
 * @brief standard base-B digit decomposition
 */
namespace standard {
    // Canonical (non-RNS) gadget decomposition
    // template <typename PolyImpl = DCRTPoly>
    std::vector<DCRTPoly> SignedDigitDecompose(
        const std::shared_ptr<CryptoParametersRNS> params, 
        const DCRTPoly& input,
        const uint32_t log_b
    ) {
        // for(const auto& q : params->GetQHatModbsk())
        const auto& params = input.GetParams();
        const auto& towers = input.GetAllElements();

        // Q
        auto Q = params->GetElementParams()->GetModulus();
        auto QHalf{Q >> 1};
        auto Q_int{Q.ConvertToInt<NativeInteger::SignedNativeInt>()};

        // Base B = 2^w
        const auto B{uint64_t(1) << log_b};
        const auto halfB{static_cast<int64_t>(B >> 1)};
        
        const auto ell = (Q.GetMSB()/log_b) + 1;
        const auto N = params->GetRingDimension();

        // Output
        std::vector<DCRTPoly> g;
        g.reserve(ell);

        for (uint32_t k = 0; k < ell; ++k) {
            g.emplace_back(params, Format::EVALUATION, true);
        }

        // Coefficient-wise decomposition
        for (size_t j = 0; j < N; ++j) {
            // Full CRT reconstruction
            BigInteger x = input.CRTInterpolateIndex(j);

            // Center lift
            if (x > QHalf) {
                x -= Q;
            }

            for (uint32_t k = 0; k < ell; ++k) {

                // Extract digit mod B
                int64_t digit =
                    static_cast<int64_t>((x % BigInteger(B)).ConvertToInt());

                if (digit >= halfB) {
                    digit -= static_cast<int64_t>(B);
                }

                x = (x - BigInteger(digit)) / BigInteger(B);

                // Store digit across all CRT towers
                for (size_t i = 0; i < towers.size(); ++i) {
                    const NativeInteger qi = params->GetElementParams()->GetParams()[i]->GetModulus();

                    NativeInteger digitCRT;
                    if (digit < 0) {
                        digitCRT = qi - NativeInteger(static_cast<uint64_t>(-digit));
                    }
                    else {
                        digitCRT = NativeInteger(static_cast<uint64_t>(digit));
                    }

                    // Must mutate tower directly (GetElementAtIndex may return const)
                    g[k].GetAllElements()[i][j] = digitCRT;
                }
            }
        }


        return g;
    }


} // namespace standard


TEST(DECOMPOSE_B, main) {
    const std::vector<int64_t> value{3};
    constexpr uint32_t LOG_B = 5;

    const auto params = params::Small<CryptoContextBGVRNS>();
    const auto cc = GenCryptoContext(params);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    const auto keys = cc->KeyGen();

    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();
    m.SetFormat(Format::EVALUATION);

    // Get gadget decomposition vector
    const auto ccRNS = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const auto mg = standard::SignedDigitDecompose(ccRNS, m, LOG_B);

    // Get inverse gadget vector
    // const auto md = 

    // Check inner product = m*m
    {

    }
}