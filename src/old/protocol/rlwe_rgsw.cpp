/**
 * demo.cpp
 *
 * End-to-end demonstration of RLWE → RGSW homomorphic expansion.
 * Exercises the full Client/Server protocol and verifies correctness
 * by decrypting each RGSW row on the Client side.
 *
 * Toy parameters (n=32) are used for speed; see comments for production values.
 *
 * Build:
 *   mkdir build && cd build
 *   cmake .. -DOpenFHE_DIR=/path/to/openfhe-development/install
 *   make
 */

#include "rlwe_rgsw.h"
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <random>

// ─────────────────────────────────────────────────────────────────────────────
// Decode a decrypted RLWE polynomial to recover the plaintext scalar b ∈ {0,1}.
//
// After HomExpand, the bottom-half row k of RGSW(b) decrypts to
//   μ = b/B^(k+1) + small error  (mod q, centred).
//
// We check the constant coefficient only (bit extracted into the constant term
// by the expansion algorithm and then recovered via RightShift of the modular
// value).  A value close to q/B^(k+1) indicates b=1; close to 0 indicates b=0.
static int RecoverBit(RingElem& decrypted, uint32_t k, const Params& p) {
    decrypted.SetFormat(COEFFICIENT);   // work in coefficient domain
    uint64_t qVal    = p.q.ConvertToInt<uint64_t>();
    uint64_t coeff0  = decrypted[0].ConvertToInt<uint64_t>();

    // Centre the value: map [qHalf, q) → [−qHalf, 0)
    int64_t centred = (coeff0 >= (qVal + 1) / 2)
                        ? (int64_t)coeff0 - (int64_t)qVal
                        : (int64_t)coeff0;

    // Expected magnitude for b=1: round(q / B^(k+1))
    int64_t expected = (int64_t)(qVal >> ((k + 1) * p.logB));

    // b=1 if |centred| is closer to `expected` than to 0.
    int64_t dist1 = std::abs(centred - expected);
    int64_t dist0 = std::abs(centred);
    return (dist1 < dist0) ? 1 : 0;
}

// ─────────────────────────────────────────────────────────────────────────────
int main() {

    // ── 1. Parameter selection ──────────────────────────────────────────────
    //
    // Production suggestion (128-bit classical security, TFHE-style):
    //   n=2048, q=2^27 NTT prime, ell=4, logB=7, ellKs=4, logBks=7, sigma=3.19
    //
    // Toy parameters (fast, not secure):
    //   n=32, q=786433 (= 3·2^18+1, NTT-friendly prime, 786433 ≡ 1 mod 64 = 2n).
    //   ell=3, logB=6 → B=64, ell*logB=18 < 20 bits of q.  ✓
    //   ellKs=3, logBks=6.
    //
    // q=786433 check: 786433 = 3 * 262144 = 3 * 2^18 + 1.  Is it prime?  Yes.
    // 786433 mod 64 = 786433 - 12288*64 = 786433 - 786432 = 1.  ✓  (≡ 1 mod 2n=64)

    const uint32_t n      = 32;
    const uint32_t ell    = 3;
    const uint32_t logB   = 6;      // B = 64
    const uint32_t ellKs  = 3;
    const uint32_t logBks = 6;
    const double   sigma  = 3.19;
    NativeInteger  q(786433ULL);

    Params p = Params::Make(n, q, ell, logB, ellKs, logBks, sigma);

    std::cout << "======================================================\n"
              << "  RLWE → RGSW Homomorphic Expansion Demo\n"
              << "======================================================\n"
              << "  n=" << n << ", q=" << q
              << ", ell=" << ell << ", B=2^" << logB
              << ", ellKs=" << ellKs << ", Bks=2^" << logBks << "\n\n";

    // ── 2. Client: key generation ───────────────────────────────────────────
    std::cout << "[Client] Sampling secret key s ∈ {0,1}^n …\n";
    RingElem secretKey = Client::SampleSecretKey(p);

    std::cout << "[Client] Generating evaluation keys (substKS + RGSW(−s)) …\n";
    EvalKey ek = Client::Setup(secretKey, p);

    // ── 3. Client: pack plaintext bits ─────────────────────────────────────
    std::mt19937 rng(0xDEADBEEF);
    std::vector<uint32_t> plainBits(n);
    for (auto& b : plainBits) b = rng() & 1u;

    std::cout << "[Client] Plaintext bits (first 16): ";
    for (uint32_t i = 0; i < 16; i++) std::cout << plainBits[i];
    std::cout << " …\n";

    std::cout << "[Client] Packing " << n << " bits into " << ell
              << " scaled RLWE ciphertexts …\n\n";
    std::vector<RLWECt> packed = Client::PackBits(plainBits, secretKey, p);

    // ── 4. SERVER: homomorphic expansion ────────────────────────────────────
    // From this point the Server only has (packed, ek) — no secret key.
    std::cout << "[Server] Running HomExpand …\n";
    std::vector<RGSWCt> rgsw = Server::HomExpand(packed, ek, p);
    std::cout << "[Server] Produced " << rgsw.size() << " RGSW ciphertexts,\n"
              << "         each with " << rgsw[0].size() << " RLWE rows.\n\n";

    // ── 5. Client: verify correctness ───────────────────────────────────────
    // Decrypt the bottom-half rows of each RGSW ciphertext and check they
    // decode to the correct bit.  In a real deployment the Client never
    // receives RGSW ciphertexts back; this is a test harness only.
    std::cout << "[Client] Verifying RGSW ciphertexts (bottom-half rows) …\n";

    uint32_t errors = 0;
    for (uint32_t i = 0; i < n; i++) {
        for (uint32_t k = 0; k < ell; k++) {
            // Bottom-half row k+ell should decrypt to bᵢ/B^(k+1).
            const RLWECt& row = rgsw[i][k + ell];
            RingElem dec = Client::Decrypt(row, secretKey, p);

            int recovered = RecoverBit(dec, k, p);
            if (recovered != (int)plainBits[i]) {
                std::cerr << "  MISMATCH at bit i=" << i
                          << " gadget level k=" << k
                          << " (expected " << plainBits[i]
                          << ", got " << recovered << ")\n";
                ++errors;
            }
        }
    }

    if (errors == 0) {
        std::cout << "[Client] All " << (n * ell) << " bottom-half checks PASSED.\n";
    } else {
        std::cerr << "[Client] " << errors << " checks FAILED.\n";
        return EXIT_FAILURE;
    }

    // Spot-check the top-half rows: row k should decrypt to bᵢ·(−s)/B^(k+1).
    // We decrypt and verify that multiplying by (−s) gives the expected result.
    std::cout << "[Client] Spot-checking top-half rows (i=0..3, k=0) …\n";
    for (uint32_t i = 0; i < std::min(n, 4u); i++) {
        const RLWECt& top_row = rgsw[i][0];    // row k=0 of top half
        RingElem dec_top = Client::Decrypt(top_row, secretKey, p);
        // dec_top ≈ bᵢ·(−s)/B¹; multiply back by (−1/bᵢ)·B to recover s.
        // For a smoke test just print the constant coefficient; it should be
        // near ±s[0]/B^1 if bᵢ=1, or near 0 if bᵢ=0.
        dec_top.SetFormat(COEFFICIENT);
        uint64_t c0   = dec_top[0].ConvertToInt<uint64_t>();
        uint64_t qVal = p.q.ConvertToInt<uint64_t>();
        int64_t  c0c  = (c0 >= (qVal+1)/2) ? (int64_t)c0-(int64_t)qVal : (int64_t)c0;
        std::cout << "  i=" << i << " bit=" << plainBits[i]
                  << "  top_row[0].coeff[0]=" << std::setw(8) << c0c << "\n";
    }

    std::cout << "\nDone.\n";
    return EXIT_SUCCESS;
}