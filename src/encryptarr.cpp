#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "../includes/HelloWorldHex.h" // Path to HelloWorldHex.h

#pragma comment(lib, "advapi32.lib")

// Encrypts the hello_world_exe array and outputs the encrypted data and key
bool EncryptData(const unsigned char* data, int dataSize, std::vector<unsigned char>& encryptedData, std::vector<unsigned char>& key) {
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;

    // Step 1: Acquire a cryptographic provider context
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error in CryptAcquireContext: " << GetLastError() << std::endl;
        return false;
    }

    // Step 2: Generate a random AES key
    if (!CryptGenKey(hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) {
        std::cerr << "Error in CryptGenKey: " << GetLastError() << std::endl;
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Export the key so it can be reused
    DWORD keySize;
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &keySize)) {
        std::cerr << "Error calculating key size for export: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    key.resize(keySize);
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, key.data(), &keySize)) {
        std::cerr << "Error in CryptExportKey: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Step 3: Calculate the buffer size required for encryption (including padding)
    DWORD bufferSize = dataSize;
    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufferSize, 0)) {
        std::cerr << "Error calculating buffer size: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Step 4: Resize encryptedData to the required buffer size and copy the data
    encryptedData.resize(bufferSize);
    memcpy(encryptedData.data(), data, dataSize);

    // Encrypt the data in place
    DWORD encryptedDataSize = dataSize; // Initial size of the data before encryption
    if (!CryptEncrypt(hKey, 0, TRUE, 0, encryptedData.data(), &encryptedDataSize, bufferSize)) {
        std::cerr << "Error in CryptEncrypt: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Ensure encryptedData is resized to the actual encrypted data size
    encryptedData.resize(encryptedDataSize);

    // Release resources
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);

    return true;
}

// Saves the encrypted array to HelloWorldHex.h
void SaveEncryptedArrayToFile(const std::vector<unsigned char>& encryptedData) {
    std::ofstream outputFile("C:\\Users\\sebastian\\Desktop\\HelloWorldHex.h"); // Save to Windows desktop
    outputFile << "#ifndef HELLOWORLDHEX_H\n#define HELLOWORLDHEX_H\n\n";
    outputFile << "unsigned char encryptedData[] = {";

    for (size_t i = 0; i < encryptedData.size(); ++i) {
        outputFile << "0x" << std::hex << (int)encryptedData[i];
        if (i != encryptedData.size() - 1) outputFile << ", ";
    }

    outputFile << "};\n\n";
    outputFile << "unsigned int encryptedDataLen = " << encryptedData.size() << ";\n\n";
    outputFile << "#endif // HELLOWORLDHEX_H\n";
    outputFile.close();
}

// Saves the encryption key to encryption_key.h
void SaveEncryptionKeyToFile(const std::vector<unsigned char>& key) {
    std::ofstream keyFile("C:\\Users\\sebastian\\Desktop\\encryption_key.h"); // Save to Windows desktop
    keyFile << "#ifndef ENCRYPTION_KEY_H\n#define ENCRYPTION_KEY_H\n\n";
    keyFile << "unsigned char key[] = {";

    for (size_t i = 0; i < key.size(); ++i) {
        keyFile << "0x" << std::hex << (int)key[i];
        if (i != key.size() - 1) keyFile << ", ";
    }

    keyFile << "};\n\n";
    keyFile << "unsigned int keyLen = " << key.size() << ";\n\n";
    keyFile << "#endif // ENCRYPTION_KEY_H\n";
    keyFile.close();
}

int main() {
    std::vector<unsigned char> encryptedData;
    std::vector<unsigned char> key;

    if (EncryptData(hello_world_exe, hello_world_exe_len, encryptedData, key)) {
        SaveEncryptedArrayToFile(encryptedData);
        SaveEncryptionKeyToFile(key);
        std::cout << "Encryption successful. Encrypted data saved to HelloWorldHex.h and key saved to encryption_key.h\n";
    } else {
        std::cerr << "Encryption failed.\n";
    }

    return 0;
}
