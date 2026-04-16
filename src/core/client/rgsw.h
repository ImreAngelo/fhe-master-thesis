#include "openfhe.h"

#define DEBUG_LOGGING

namespace Client {
    using namespace lbcrypto;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

// #if !defined(TEST_INTERNAL_FUNCTIONS)
//  protected: 
// #endif
    /**
     * @brief Encrypt message as RGSW ciphertext
     * 
     * @todo Look into SIMD operations for constructing (top) rows
     * 
     * @param keys Public/private keys needed
     * @param msg Packed plaintext message to encrypt
     * @param B Gadget base (default 2)
     */
    RGSWCiphertext<DCRTPoly> EncryptRGSW(
        CryptoContext<DCRTPoly>& cc,
        KeyPair<DCRTPoly>& keys, // TODO: Only needs secret key
        std::vector<int64_t> msg,
        uint64_t B = 2 // TODO: create tests for different bases
    ) {
        auto t = NativeInteger(cc->GetCryptoParameters()->GetPlaintextModulus());
        auto ell = msg.size();
        
        RGSWCiphertext<DCRTPoly> G(2*ell);
        NativeInteger b_ctr(1), gi;

        // Extract secret s
        // Elements of RLWE is represented as (b, a) so s = element[0]
        auto sk_poly = keys.secretKey->GetPrivateElement();
        sk_poly.SetFormat(Format::EVALUATION); // TODO: probably is evaluation already.. (confirm)
        auto& s = sk_poly.GetElementAtIndex(0);

        // NOTE: code is 0-index, formulas are 1-indexed so i = i + 1
        for (size_t i = 0; i < ell; i++) {
            // Find 1/B^i mod t
            b_ctr = b_ctr.ModMul(B, t);
            gi = b_ctr.ModInverse(t);

            // Bottom L rows: msg/B^i
            std::vector<int64_t> row(ell);
            for(size_t j = 0; j < ell; j++) {
                auto val = gi.ModMul(NativeInteger(msg[j]), t);
                row[j] = val.ConvertToInt<int64_t>();
            }

            Plaintext bottom = cc->MakePackedPlaintext(row);
            G[i + ell] = cc->Encrypt(keys.secretKey, bottom);
            
            // Top L rows: -s * msg/B^i
            for(size_t j = 0; j < ell; j++) {
                auto val = (t - s[j]).ModMul(row[j], t);
                row[j] = val.ConvertToInt<int64_t>();
            }

            Plaintext top = cc->MakePackedPlaintext(row);
            G[i] = cc->Encrypt(keys.secretKey, top);
        }
        
#if defined(DEBUG_LOGGING)
        // TODO: move to test
        std::cout << "G: " << std::endl;
        for(const auto& row : G) {
            Plaintext decrytedRow;
            cc->Decrypt(keys.secretKey, row, &decrytedRow);
            decrytedRow->SetLength(ell);
            std::cout << decrytedRow << std::endl;
        }
#endif

        return G;
    }

    RGSWCiphertext<DCRTPoly> EncryptRGSW_NTT(
        CryptoContext<DCRTPoly>&    cc,
        const PrivateKey<DCRTPoly>& sk,
        const std::vector<int64_t>& msg,
        uint64_t B = 2
    ) {
        const auto& cryptoParams = cc->GetCryptoParameters();
        const uint64_t t      = cryptoParams->GetPlaintextModulus();
        const size_t   N      = cc->GetRingDimension();
        const size_t   nSlots = cryptoParams->GetEncodingParams()->GetBatchSize();
        const size_t   ell    = cryptoParams->GetElementParams()->GetParams().size();

        RGSWCiphertext<DCRTPoly> Y(2 * ell);

        // ── s in coefficient domain, balanced ────────────────────────────────
        auto sk_poly = sk->GetPrivateElement();
        sk_poly.SetFormat(Format::COEFFICIENT);
        const auto& s_elem = sk_poly.GetElementAtIndex(0);
        const int64_t q0   = s_elem.GetModulus().ConvertToInt<int64_t>();

        std::vector<int64_t> s_coeffs(N);
        for (size_t k = 0; k < N; k++) {
            int64_t c = s_elem[k].ConvertToInt<int64_t>();
            if (c > q0 / 2) c -= q0;
            s_coeffs[k] = c;
        }

        // ── s in slot domain: build NativePoly in Z_t[X]/(X^N+1), then NTT ──
        // FIX: construct ILNativeParams directly instead of extracting from
        // a DCRTPoly plaintext (which crashes with GetElement<NativePoly>()).
        // t ≡ 1 (mod 2N) guarantees the NTT roots exist in Z_t.
        auto pt_params = std::make_shared<ILNativeParams>(2 * N, NativeInteger(t));
        NativePoly s_plain(pt_params, Format::COEFFICIENT, true);
        for (size_t k = 0; k < N; k++) {
            s_plain[k] = (s_coeffs[k] < 0)
                    ? NativeInteger(t - 1)   // -1 mod t (ternary key)
                    : NativeInteger((uint64_t)s_coeffs[k]);
        }
        s_plain.SetFormat(Format::EVALUATION);
        // s_plain[j] is now s(ω^j) mod t, consistent with packed slot j

        // ── pad msg to nSlots ─────────────────────────────────────────────────
        std::vector<int64_t> mu(nSlots, 0);
        for (size_t j = 0; j < std::min(msg.size(), nSlots); j++)
            mu[j] = ((msg[j] % (int64_t)t) + t) % t;

        // ── gadget rows ───────────────────────────────────────────────────────
        uint64_t Bi = 1;
        for (size_t i = 0; i < ell; i++) {
            if (i > 0) Bi = Bi * B % t;

            std::vector<int64_t> bot_slots(nSlots), top_slots(nSlots);
            for (size_t j = 0; j < nSlots; j++) {
                const uint64_t bot_j  = (uint64_t)mu[j] * Bi % t;
                const uint64_t s_j    = s_plain.GetValues()[j].ConvertToInt<uint64_t>();
                const uint64_t neg_sj = (t - s_j) % t;

                bot_slots[j] = (int64_t)bot_j;
                top_slots[j] = (int64_t)(neg_sj * bot_j % t);
            }

            Y[i]       = cc->Encrypt(sk, cc->MakePackedPlaintext(top_slots));
            Y[i + ell] = cc->Encrypt(sk, cc->MakePackedPlaintext(bot_slots));
        }
        
#if defined(DEBUG_LOGGING)
        // TODO: move to test
        std::cout << "G: " << std::endl;
        for(const auto& row : Y) {
            Plaintext decrytedRow;
            cc->Decrypt(sk, row, &decrytedRow);
            decrytedRow->SetLength(ell);
            std::cout << decrytedRow << std::endl;
        }
#endif

        return Y;
    }
}

namespace Server {
    using namespace lbcrypto;
    
    template <typename T>
    using RLWECiphertext = Ciphertext<T>;

    template <typename T>
    using RGSWCiphertext = std::vector<Ciphertext<T>>;

    /**
     * @brief Evaluate external product homomorphically
     */
    Ciphertext<DCRTPoly> EvalExternalProduct(
        CryptoContext<DCRTPoly>& cc,
        PublicKey<DCRTPoly>& publicKey,
        RLWECiphertext<DCRTPoly> rlwe,
        RGSWCiphertext<DCRTPoly> rgsw,
        size_t ell = 4,
        uint64_t B = 2 // TODO: get all params from m_params

    ) {
        // auto t = NativeInteger(cc->GetCryptoParameters()->GetPlaintextModulus());
        // // auto ell = msg.size(); // TODO: Get from parameters!
        
        // NativeInteger g_inv(B);
        
        // // TODO:
        // // TEST: Verify that G^{-1}(x) * G = RLWE(x)
        // //       (a * g^{-1} * g = )
        
        // // Extract (a, b) from RLWE
        // auto elements = rlwe->GetElements();
        // auto a = elements[1]; // .ToNativePoly()
        // auto b = elements[0]; // TODO: Use native vector for optimization

        // for (size_t i = 0; i < ell; i++, g_inv = g_inv.ModMul(B, t)) {
        //     auto el = a.GetElementAtIndex(i).ToNativePoly();
        //     auto v = g_inv.ModMul(el, t);
            
        //     // .. * Y
        //     // auto row = rgsw[i]; // top row i
        // }

        return rlwe;
    }
}