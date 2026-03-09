#include "openfhe.h"
#include "testing/Timer.h"

using namespace lbcrypto;
using namespace testing;

// TODO: Pass via make test + cmake
#define TEST
#ifdef TEST
#define TEST_ONE
#define TEST_TWO
#endif

// Return MSE between two vectors
template <typename T>
inline T mean_square_error(std::vector<T> a, std::vector<T> b)
{
    T error = 0;
    for(std::size_t i = 0; i < a.size(); i++) {
        auto e = (a[i] - b[i])/2;
        error += e*e;
    } 
    return error;
}

// Convert plaintext to vector of bools
// Assume T = double unless explicitly set
template <typename T>
inline std::vector<bool> boolify(std::vector<T> & vec, T threshold = 0)
{
    std::vector<bool> out;
    out.reserve(vec.size());

    // x[i] >= 0.5
    std::transform(vec.begin(), vec.end(), std::back_inserter(out), [threshold](T d) -> bool {
        return d >= threshold;
    });

    return out;
}

namespace Server
{
    // Compute minimax coefficients for domain [delta, 1]
    // p(x) = c1*x + c3*x^3 approximates sign(x) on [delta, 1]
    template <typename T>
    Ciphertext<T> minimax_seed(CryptoContext<T> cc, Ciphertext<T> x, double delta)
    {
        double S  = 1 + delta + delta*delta;
        double xs = std::sqrt(S / 3.0);
        double c3 = -6.0 / (2*S*xs + 3*(S - 1));
        double c1 = -c3 * S;

        auto x2 = cc->EvalMult(x, x);
        auto x3 = cc->EvalMult(x2, x);

        auto result = cc->EvalMult(x,  c1);
        cc->EvalAddInPlace(result, cc->EvalMult(x3, c3));

        return result;
    }

    // Return wether x > 0 by mapping x_i -> {-1, 1}, 
    // given that x is in [-1, -delta) U (delta, 1]
    template <typename T>
    Ciphertext<T> compare(CryptoContext<T> cc, Ciphertext<T> x, uint32_t iterations = 2, double delta = 0.1)
    {
        // Seed minimax
        x = minimax_seed(cc, x, delta);

        // Newton's method iterations, converges to sign(x)
        for (uint32_t i = 0; i < iterations; i++) {
            auto a = cc->EvalMult(x, 0.5);
            auto b = cc->EvalMult(x, x);
            b = cc->EvalSub(3.0, b);
            x = cc->EvalMult(a, b);
        }
        
        return x;
    }
    
    // Return wether x > 0 by mapping x_i -> {-1, 1}, 
    // given that x is in [-1, -delta) U (delta, 1]
    template <typename T>
    std::tuple<Ciphertext<T>, Ciphertext<T>> 
        sort_two_unpacked(CryptoContext<T> cc, Ciphertext<T> a, Ciphertext<T> b, uint32_t iterations = 2, double delta = 0.1)
    {
        // Check sign(a - b)
        // diff a - b must be in [-1, 1]
        auto diff = cc->EvalSub(a, b);
        auto sign = compare(cc, diff, iterations, delta);

        // Circuit switch positions
        auto sum = cc->EvalAdd(a, b);
        auto s_diff = cc->EvalMult(sign, diff);

        auto min = cc->EvalMult(cc->EvalSub(sum, s_diff), 0.5);
        auto max = cc->EvalMult(cc->EvalAdd(sum, s_diff), 0.5);
        
        return std::tuple(min, max);
    }

    // Return wether x > 0 by mapping x_i -> {-1, 1}, 
    // given that x is in [-1, -delta) U (delta, 1]
    template <typename T>
    Ciphertext<T> sort_two(CryptoContext<T> cc, Ciphertext<T> x, uint32_t iterations = 2, double delta = 0.1)
    {
        // Check sign(a - b)
        auto x_rot = cc->EvalAtIndex(x, 1);
        auto diff = cc->EvalSub(x, x_rot);
        auto s = compare(cc, diff, iterations, delta);

        auto sum = cc->EvalAdd(x, x_rot);
        auto s_diff = cc->EvalMult(s, diff);

        // Circuit switch positions
        // min in slot 0, max in slot 1
        auto min = cc->EvalMult(cc->EvalSub(sum, s_diff), 0.5);
        auto max = cc->EvalMult(cc->EvalAdd(sum, s_diff), 0.5);

        auto mask_min = cc->MakeCKKSPackedPlaintext(std::vector<double>{1.0, 0.0});
        auto mask_max = cc->MakeCKKSPackedPlaintext(std::vector<double>{0.0, 1.0});

        return cc->EvalAdd(
            cc->EvalMult(min, mask_min),
            cc->EvalMult(max, mask_max)
        );
    }
}


namespace Client 
{
    /** 
     * Sort (not packed)
     */ 
    template <typename T>
    std::vector<T> sort_two_unpacked(T a, T b, uint32_t multDepth = 10, uint32_t iterations = 2)
    {
        // Params from example "simple real numbers"
        uint32_t scaleModSize = 50;
        uint32_t batchSize = 2;
        
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetBatchSize(batchSize);
        
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        
        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        
        // Generate encryption keys
        auto keys = cc->KeyGen();
        
        // Relinearization key
        cc->EvalMultKeyGen(keys.secretKey);

        // For minimax, delta should be the infimum for |a-b|
        auto delta = std::abs(a - b);

        // Encoding and encryption
        // TODO: Scale to [-1, 1]
        std::vector<double> va = { a };
        std::vector<double> vb = { b };

        Plaintext pa = cc->MakeCKKSPackedPlaintext(va);
        Plaintext pb = cc->MakeCKKSPackedPlaintext(vb);

        auto ca = cc->Encrypt(keys.publicKey, pa);
        auto cb = cc->Encrypt(keys.publicKey, pb);

        std::cout << "Input: " << a << ", " << b << std::endl;

        // Results
        auto [rca, rcb] = Server::sort_two_unpacked(cc, ca, cb, 2, delta);

        Plaintext ra;
        cc->Decrypt(keys.secretKey, rca, &ra);
        ra->SetLength(batchSize);
        
        Plaintext rb;
        cc->Decrypt(keys.secretKey, rcb, &rb);
        rb->SetLength(batchSize);

        return std::vector {
            ra->GetRealPackedValue()[0],
            rb->GetRealPackedValue()[0],
        };
    }

    /**
     * Sort with packing
     */
    template <typename T>
    std::vector<T> sort_two(T a, T b, uint32_t multDepth = 10, uint32_t iterations = 2)
    {
        // Params from example "simple real numbers"
        uint32_t scaleModSize = 50;
        uint32_t batchSize = 2;
        
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetBatchSize(batchSize);
        
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        
        // Enable the features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        
        // Generate encryption keys
        auto keys = cc->KeyGen();
        
        // Relinearization key
        cc->EvalMultKeyGen(keys.secretKey); 
        cc->EvalRotateKeyGen(keys.secretKey, {1});

        // For minimax, delta should be the infimum for |a-b|
        auto delta = std::abs(a - b);

        // Encoding and encryption
        // TODO: Scale to [-1, 1]
        std::vector<double> x = { a, b };

        Plaintext plaintext = cc->MakeCKKSPackedPlaintext(x);

        auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

        std::cout << "Input: " << a << ", " << b << std::endl;

        // Results
        auto sorted_ciphertext = Server::sort_two(cc, ciphertext, iterations, delta);

        Plaintext result;
        cc->Decrypt(keys.secretKey, sorted_ciphertext, &result);
        result->SetLength(batchSize);

        return result->GetRealPackedValue();
    }
}

int main()
{
    std::vector<double> sorted_vec;
    sorted_vec.reserve(2);

#ifdef TEST_ONE
{
    Timer t("Test #1");
    sorted_vec = Client::sort_two_unpacked(0.25, -0.5);
    std::cout << "Output #1: " << sorted_vec[0] << ", " << sorted_vec[1] << std::endl;
}
#endif
#ifdef TEST_TWO
{
    Timer t("Test #2");
    sorted_vec = Client::sort_two(0.25, -0.5);
    std::cout << "Output #2: " << sorted_vec[0] << ", " << sorted_vec[1] << std::endl;
}
#endif

    return 0;
}
