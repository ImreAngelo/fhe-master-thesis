#include "openfhe.h"
#include "testing/Timer.h"

using namespace lbcrypto;
using testing::Timer;

template <typename T>
extern Ciphertext<T> EvalDotProduct(CryptoContext<T>, Ciphertext<T>, Ciphertext<T>);

int main() 
{
    // Sample Program: Step 1 - Set CryptoContext
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetPlaintextModulus(65537);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    // Sample Program: Step 2 - Key Generation

    KeyPair<DCRTPoly> keyPair;
    keyPair = cryptoContext->KeyGen();

    // relinearization key + rotation-sum key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalSumKeyGen(keyPair.secretKey);

    // Sample Program: Step 3 - Encryption
    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);
    
    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

    // Sample Program: Step 4 - Evaluation

    auto ciphertextResult = EvalDotProduct(cryptoContext, ciphertext1, ciphertext2);

    // Sample Program: Step 5 - Decryption

    Plaintext plaintextResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
    plaintextResult->SetLength(1);

    // Printing

    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;

    // Output results

    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "#1 * #2 = " << plaintextResult->GetPackedValue()[0] << std::endl;

    int64_t target = 0;
    {
        Timer t1("Non-HE calculation");
        for(size_t i = 0; i < vectorOfInts1.size(); i++) {
            target += vectorOfInts1[i] * vectorOfInts2[i];
        }
    }

    std::cout << "Real sum = " << target << std::endl;

    return 0;
}


template <typename T>
Ciphertext<T> EvalDotProduct(
    CryptoContext<T> cc,
    Ciphertext<T> a,
    Ciphertext<T> b
) 
{
    Timer t("Dot product");

    auto result = cc->EvalMult(a, b);

    // Rotate-and-sum: accumulates all slots into slot 0.
    // EvalSum rotates by 1, 2, 4, ... and adds — O(log n) operations.
    result = cc->EvalSum(result, a->GetEncodingParameters()->GetBatchSize());

    return result;
}