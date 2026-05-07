#define TEST_INTERNAL_FUNCTIONS
#define CENTER(integer, modulus) (((integer) > (modulus) / 2) ? ((integer % (2*modulus)) - (modulus)) : (integer))

#include "core/context.h"
#include "core/helpers.h"
#include "core/params.h"
#include "core/rgsw.h"

#include "../cli_params.h"

#include <cstdint>
#include <cmath>
#include <iostream>


using namespace lbcrypto;

namespace BV {
    // BV-RNS gadget (Appendix B.2.1 of eprint 2021/204).
    //
    //   D_Q(a)_i = [a · (Q/q_i)^{-1}]_{q_i}              (decomposition; "small" digit)
    //   P_Q(b)_i = [b · (Q/q_i)]_Q                       (gadget scaled by b)
    //
    // Identity: <D_Q(a), P_Q(b)> ≡ a·b (mod Q).
    //
    // RNS observation: P_Q(b)_i is zero in every tower j ≠ i because q_j | Q/q_i.
    // That is why D_Q(a)_i can be stored with only tower i populated — the other
    // towers never contribute to the inner product.

    inline std::vector<NativeInteger> InverseGadgetScalars(const CryptoContext<DCRTPoly>& cc) {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto Q = params->GetElementParams()->GetModulus();
        const auto q = params->GetElementParams()->GetParams();

        std::vector<NativeInteger> result;
        result.reserve(q.size());
        for (size_t i = 0; i < q.size(); i++) {
            const auto qi = q[i]->GetModulus();
            result.push_back((Q / BigInteger(qi)).Mod(qi).ModInverse(qi));
        }
        return result;
    }

    inline std::vector<NativeInteger> GadgetScalars(const CryptoContext<DCRTPoly>& cc) {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto Q = params->GetElementParams()->GetModulus();
        const auto q = params->GetElementParams()->GetParams();

        std::vector<NativeInteger> result;
        result.reserve(q.size());
        for (size_t i = 0; i < q.size(); i++) {
            const auto qi = q[i]->GetModulus();
            result.push_back((Q / BigInteger(qi)).Mod(qi));
        }
        return result;
    }

    /// D_Q(a)_i = [a · (Q/q_i)^{-1}]_{q_i}, embedded in tower i (other towers zero).
    inline std::vector<DCRTPoly> Decompose(const CryptoContext<DCRTPoly>& cc, const DCRTPoly& a) {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto q = params->GetElementParams()->GetParams();
        const auto inv = InverseGadgetScalars(cc);

        std::vector<DCRTPoly> d;
        d.reserve(q.size());
        for (size_t i = 0; i < q.size(); i++) {
            const auto qi = q[i]->GetModulus();
            DCRTPoly di(params->GetElementParams(), a.GetFormat(), true);
            auto tower = a.GetElementAtIndex(i).Times(inv[i]).Mod(qi);
            di.SetElementAtIndex(i, tower);
            d.push_back(std::move(di));
        }
        return d;
    }

    /// P_Q(b)_i = [b · (Q/q_i)]_Q. In RNS form only tower i is non-zero.
    inline std::vector<DCRTPoly> GadgetMul(const CryptoContext<DCRTPoly>& cc, const DCRTPoly& b) {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto q = params->GetElementParams()->GetParams();
        const auto g = GadgetScalars(cc);

        std::vector<DCRTPoly> P;
        P.reserve(q.size());
        for (size_t i = 0; i < q.size(); i++) {
            const auto qi = q[i]->GetModulus();
            DCRTPoly Pi(params->GetElementParams(), b.GetFormat(), true);
            auto tower = b.GetElementAtIndex(i).Times(g[i]).Mod(qi);
            Pi.SetElementAtIndex(i, tower);
            P.push_back(std::move(Pi));
        }
        return P;
    }

    /// Unscaled gadget vector g_i = [Q/q_i]_Q (i.e. P_Q(1)).
    /// Useful for verifying the reconstruction identity <D_Q(a), g> ≡ a (mod Q).
    inline std::vector<DCRTPoly> GadgetVector(const CryptoContext<DCRTPoly>& cc) {
        const auto params = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        const auto q = params->GetElementParams()->GetParams();
        const auto g = GadgetScalars(cc);

        std::vector<DCRTPoly> out;
        out.reserve(q.size());
        for (size_t i = 0; i < q.size(); i++) {
            // Constant polynomial g_i ∈ R_Q: only tower i is non-zero, holding the constant g[i].
            DCRTPoly poly(params->GetElementParams(), Format::COEFFICIENT, true);
            auto tower = poly.GetElementAtIndex(i);
            tower[0] = g[i];
            poly.SetElementAtIndex(i, tower);
            poly.SetFormat(Format::EVALUATION);
            out.push_back(std::move(poly));
        }
        return out;
    }

    inline DCRTPoly InnerProduct(const std::vector<DCRTPoly>& u, const std::vector<DCRTPoly>& v) {
        if (u.empty() || u.size() != v.size())
            throw std::runtime_error("Vector sizes are invalid or do not match.");

        DCRTPoly result(u[0].GetParams(), u[0].GetFormat(), true);
        for (size_t i = 0; i < u.size(); i++)
            result += u[i] * v[i];
        return result;
    }
}


inline CCParams<CryptoContextRGSWBGV> GetParams() {
    CCParams<CryptoContextRGSWBGV> params;
    params.SetMultiplicativeDepth(test_cli::g_mult_depth.value_or(3));
    params.SetPlaintextModulus(test_cli::g_plaintext_modulus.value_or(65537));
    params.SetRingDim(test_cli::g_ring_dim.value_or(1 << 14));
    // params.SetNumLargeDigits(2);

    params.SetMaxRelinSkDeg(0); // Force no relinearization keys

    // RGSW rows are built by hand → avoid per-level scaling (S_L = 1 needed).
    params.SetScalingTechnique(test_cli::g_scaling_technique.value_or(FIXEDMANUAL));

    DEBUG_PRINT("Depth = " << params.GetMultiplicativeDepth());
    DEBUG_PRINT("Ring Dim. = " << params.GetRingDim());
    DEBUG_PRINT("Plaintext mod = " << params.GetPlaintextModulus());

    return params;
}

/**
 * @brief Verify the BV-RNS gadget identities for an arbitrary plaintext element.
 *
 *   1. <D_Q(m), g>      ≡ m   (mod Q)   — reconstruction
 *   2. <D_Q(m), P_Q(m)> ≡ m·m (mod Q)   — multiplicative pairing
 */
inline void RunTest(const std::vector<int64_t>& value) {
    const CCParams<CryptoContextRGSWBGV> params = GetParams();
    auto cc = Context::GenExtendedCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);

    cc->KeyGen();

    Plaintext pt = cc->MakePackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();
    m.SetFormat(Format::EVALUATION);

    const auto d = BV::Decompose(cc, m);

    // Identity 1: reconstruction
    const auto g = BV::GadgetVector(cc);
    ASSERT_EQ(BV::InnerProduct(d, g), m);

    // Identity 2: <D(m), P(m)> = m·m
    const auto P = BV::GadgetMul(cc, m);
    DCRTPoly mm = m * m;
    ASSERT_EQ(BV::InnerProduct(d, P), mm);
}

TEST(RGSW_RNS_BV, b0)    { RunTest({ 0 }); }
TEST(RGSW_RNS_BV, b1)    { RunTest({ 1 }); }
TEST(RGSW_RNS_BV, multi) { RunTest({ 1, 2, 3, 4, 5, 6, 7, 8 }); }

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (int rc = test_cli::parse_args(argc, argv)) return rc;
    return RUN_ALL_TESTS();
}
