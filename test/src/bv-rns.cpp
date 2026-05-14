#include "openfhe.h"

using namespace lbcrypto;

using RGSWCiphertext = std::vector<Ciphertext<DCRTPoly>>;

class BVContext {
public:
    explicit BVContext(const CryptoContext<DCRTPoly>& cc, const usint ell = 1) 
        : m_params(cc), m_ell(ell), m_logB(computeLogB(cc, ell)), 
          m_QhatB(generatePowerTable(cc, ell)), m_decompB(generateDecompositionTable(cc, ell))
    {};

    RGSWCiphertext Encrypt(const PublicKey<DCRTPoly>& publicKey, const Plaintext& plaintext) const {
        const auto zero = (plaintext->GetEncodingType() == PlaintextEncodings::COEF_PACKED_ENCODING)
            ? m_params->MakeCoefPackedPlaintext({0})
            : m_params->MakePackedPlaintext({0});

        const auto mg = PowerOfBase(plaintext->GetElement<DCRTPoly>());

        std::vector<Ciphertext<DCRTPoly>> rows;
        rows.reserve(2 * mg.size());

        // Z + mG
        for(size_t col = 0; col < 2; col++) {
            for(const auto& mgi : mg) {
                auto z = m_params->Encrypt(publicKey, zero);
                z->GetElements()[col] += mgi;
                rows.push_back(std::move(z));
            }
        }

        return rows;
    }

    Ciphertext<DCRTPoly> EvalExternalProduct(const Ciphertext<DCRTPoly>& rlwe, const RGSWCiphertext& rgsw) const {
        const auto& elements = rlwe->GetElements();

        const auto dec0 = Decompose(elements[0]);
        const auto dec1 = Decompose(elements[1]);

        const size_t d = dec0.size();

        DCRTPoly res0(elements[0].GetParams(), Format::EVALUATION, true);
        DCRTPoly res1(elements[1].GetParams(), Format::EVALUATION, true);

        // Parallelize polynomial multiplications
        std::vector<DCRTPoly> prod0(d, res0);
        std::vector<DCRTPoly> prod1(d, res1);

        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(d))
        for (size_t i = 0; i < d; i++) {
            // First d rows correspond to Decompose(c_0)
            prod0[i]  = rgsw[i]->GetElements()[0] * dec0[i];
            prod1[i]  = rgsw[i]->GetElements()[1] * dec0[i];

            // Next d rows correspond to Decompose(c_1)
            prod0[i] += rgsw[i + d]->GetElements()[0] * dec1[i];
            prod1[i] += rgsw[i + d]->GetElements()[1] * dec1[i];
        }

        // Accumulate results sequentially 
        for (size_t i = 0; i < d; i++) {
            res0 += prod0[i];
            res1 += prod1[i];
        }

        auto result = rlwe->Clone();
        result->GetElements()[0] = std::move(res0);
        result->GetElements()[1] = std::move(res1);

        return result;
    }

    RGSWCiphertext EvalInternalProduct(const RGSWCiphertext& lhs, const RGSWCiphertext& rhs) const {
        RGSWCiphertext result = lhs;
        for(auto& rlwe : result) rlwe = EvalExternalProduct(rlwe, rhs);
        return result;
    }

private:
    /// @brief Calculates the base needed for ell number of digits to represent max{q[i]}
    static usint computeLogB(const CryptoContext<DCRTPoly>& cc, const usint ell) {
        const auto& params = cc->GetCryptoParameters()->GetElementParams()->GetParams();
        usint max_msb = 0;
        for (const auto& qi : params) {
            usint msb = qi->GetModulus().GetMSB();
            if (msb > max_msb) max_msb = msb;
        }
        return (max_msb + ell - 1) / ell;
    }

    static usint computeEll(const CryptoContext<DCRTPoly>& cc, const usint logB) {
        const auto msb = cc->GetCryptoParameters()->GetElementParams()->GetModulus().GetMSB();
        return msb / logB + 1;
    }

    /// @brief Generate the factors (Q/qi)B^i
    static std::vector<BigInteger> generatePowerTable(const CryptoContext<DCRTPoly>& cc, const usint ell) {
        const auto& Q = cc->GetElementParams()->GetModulus();
        const auto& q = cc->GetElementParams()->GetParams();
        const auto B = BigInteger(1 << computeLogB(cc, ell));

        DEBUG_PRINT("B: " << B);
        
        // Prepare B^i
        std::vector<BigInteger> powersOfB(ell, 1);
        for(usint i = 1; i < ell; i++) {
            powersOfB[i] = powersOfB[i - 1] * B;
        }

        // Prepare Q/q_i * B^i 
        std::vector<BigInteger> table(q.size() * ell);
        
        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(q.size()))
        for(usint i = 0; i < q.size(); i++) {
            const auto qi = q[i]->GetModulus();
            const auto qHat = Q / BigInteger(qi);

            for(usint j = 0; j < ell; j++) {
                table[i * ell + j] = qHat * powersOfB[j];
            }
        }

        return table;
    }

    /// @todo Generate the factors (Q/qi)^{-1} / B^i mod q_i
    static std::vector<BigInteger> generateDecompositionTable(const CryptoContext<DCRTPoly>& cc, const usint ell) {
        const auto& q = cc->GetElementParams()->GetParams();
        std::vector<BigInteger> table(q.size() * ell);

        // ...

        return table;
    }

protected: 
    const CryptoContext<DCRTPoly>& m_params;
    
    /// @brief wrt. max{q_i} not Q
    const usint m_ell; 
    const usint m_logB;

    /// @brief (Q/qi) B^i
    const std::vector<BigInteger> m_QhatB;

    /// @brief (Q/qi)^{-1} * B^i mod q_i
    const std::vector<BigInteger> m_decompB;

public:
    usint GetEll() const { return m_ell; }
    usint GetLogB() const { return m_logB; }

public:
    /// @brief Returns a * {(Q/q0), (Q/q0) B, ... (Q/qi) B^ell, (Q/q1), ... (Q/q_k) B^ell }
    std::vector<DCRTPoly> PowerOfBase(const DCRTPoly& input) const {
        const auto& q = m_params->GetElementParams()->GetParams();
        const auto len = m_ell * q.size();
        
        DCRTPoly m = input.Clone();
        m.SetFormat(Format::COEFFICIENT);

        std::vector<DCRTPoly> p(len, DCRTPoly(m.GetParams(), Format::EVALUATION, true));
 
        // For p[i], only the i-th tower is non-zero
        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(len))
        for(uint32_t i = 0; i < len; i++) {
            uint32_t tower = i / m_ell;
            DCRTPoly poly(m.GetParams(), Format::COEFFICIENT, true);
            poly.GetAllElements()[tower] = m.GetAllElements()[tower].Times(m_QhatB[i]);
            poly.SetFormat(Format::EVALUATION);
            p[i] = std::move(poly);
        }

        return p;
    }

    /// @brief Signed digit decomposition in [-q/2, q/2)
    /// @todo Major refactor needed!
    std::vector<DCRTPoly> Decompose(const DCRTPoly& input) const {
        const auto& params = std::dynamic_pointer_cast<CryptoParametersRNS>(m_params->GetCryptoParameters());
        const auto& factors = params->GetQlHatInvModq(1);
        const auto& q = m_params->GetElementParams()->GetParams();
        const auto qSize = q.size();
        
        const int64_t b_val = 1LL << m_logB;
        const int64_t b_half = b_val >> 1;

        DCRTPoly m = input.Clone();
        m.SetFormat(Format::COEFFICIENT);
        std::vector<DCRTPoly> d(qSize * m_ell, m);

        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(qSize))
        for(uint32_t i = 0; i < qSize; i++) {
            auto di_tower = m.GetAllElements()[i].Times(factors[i]);
            uint64_t qi = m.GetAllElements()[i].GetModulus().ConvertToInt();
            uint64_t qi_half = qi >> 1;

            // 1. Center the values into [-qi/2, qi/2) to prevent carry overflow
            std::vector<int64_t> current_vals(di_tower.GetLength());
            for(uint32_t coef = 0; coef < di_tower.GetLength(); coef++) {
                uint64_t val = di_tower[coef].ConvertToInt();
                if (val > qi_half) {
                    current_vals[coef] = (int64_t)val - (int64_t)qi;
                } else {
                    current_vals[coef] = (int64_t)val;
                }
            }

            for(uint32_t j = 0; j < m_ell; j++) {
                DCRTPoly dij(m.GetParams(), Format::COEFFICIENT, true);
                std::vector<int64_t> signed_digits(di_tower.GetLength());
                
                // 2. Extract digits
                for(uint32_t coef = 0; coef < di_tower.GetLength(); coef++) {
                    int64_t val = current_vals[coef];
                    int64_t digit;
                    
                    if (j == m_ell - 1) {
                        // Last digit: Absorb the remaining value to prevent dropping the carry
                        digit = val;
                        current_vals[coef] = 0; 
                    } else {
                        // True mathematical modulo B
                        digit = val % b_val;
                        if (digit < 0) digit += b_val;
                        
                        // Shift to [-B/2, B/2)
                        if (digit >= b_half) {
                            digit -= b_val;
                        }
                        current_vals[coef] = (val - digit) / b_val;
                    }
                    signed_digits[coef] = digit;
                }

                // 3. BROADCAST the safe digits
                for(uint32_t k = 0; k < qSize; k++) {
                    auto kParams = m.GetAllElements()[k].GetParams();
                    NativePoly limb(kParams, Format::COEFFICIENT, true);
                    uint64_t q_k = kParams->GetModulus().ConvertToInt();
                    
                    for(uint32_t coef = 0; coef < di_tower.GetLength(); coef++) {
                        int64_t digit = signed_digits[coef];
                        limb[coef] = (digit < 0) ? (q_k - (uint64_t)(-digit)) : (uint64_t)digit;
                    }
                    dij.GetAllElements()[k] = std::move(limb);
                }
                
                dij.SetFormat(Format::EVALUATION);
                d[i * m_ell + j] = std::move(dij);
            }
        }
        return d;
    }

    // DEBUG_PRINT(input.ApproxScaleAndRound())
};

TEST(DECOMPOSE, main) {
    constexpr int64_t val = 1;
    const std::vector<int64_t> value{val};

    auto params = params::Small<CryptoContextBGVRNS>();
    params.SetRingDim(16); // For printing

    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    const auto keys = cc->KeyGen();

    const auto bv = BVContext(cc, 2);
    const Plaintext pt = cc->MakeCoefPackedPlaintext(value);
    DCRTPoly m = pt->GetElement<DCRTPoly>();

    /* Gadget Property */ {
        const auto dm = bv.Decompose(m);
        const auto pm = bv.PowerOfBase(m);

        ASSERT_EQ(dm.size(), pm.size()) << "Size mismatch between P(m) and D(m)";

        DCRTPoly mm = dm[0] * pm[0];

        for(uint32_t i = 1; i < dm.size(); i++) {
            mm += dm[i] * pm[i];
        }

        ASSERT_EQ(mm, m * m);
    }

    /* External Product */ {
        DEBUG_TIMER("External Product");

        const auto rgsw = bv.Encrypt(keys.publicKey, pt);
        const auto rlwe = cc->Encrypt(keys.publicKey, pt);

        const auto result = bv.EvalExternalProduct(rlwe, rgsw);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, result, &decrypted);
        decrypted->SetLength(1);

        DEBUG_PRINT(decrypted);
        
        const auto expected = cc->MakeCoefPackedPlaintext({val * val});
        ASSERT_EQ(decrypted, expected);
    }

    /* Internal Product */ {
        DEBUG_TIMER("Internal Product");

        const auto rgsw = bv.Encrypt(keys.publicKey, pt);
        const auto prod = bv.EvalInternalProduct(rgsw, rgsw);

        const auto one = cc->MakeCoefPackedPlaintext({1});
        const auto identity = cc->Encrypt(keys.publicKey, one);
        const auto result = bv.EvalExternalProduct(identity, prod);

        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, result, &decrypted);
        decrypted->SetLength(1);

        DEBUG_PRINT(decrypted);
    }
}
