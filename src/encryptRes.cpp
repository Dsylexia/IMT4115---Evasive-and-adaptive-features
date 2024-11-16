#include <windows.h>
#include <wincrypt.h>
#include <compressapi.h>  // Include Windows Compression API
#include <iostream>
#include <vector>
#include <fstream>
#include "../includes/Resource.h"  // Include the header for program resources

#pragma comment(lib, "advapi32.lib")  // For CryptoAPI
#pragma comment(lib, "Cabinet.lib")   // For Windows Compression API

// Helper function to write buffer to a file
void WriteBufferToFile(const std::string& filePath, const std::vector<BYTE>& buffer) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[error] Failed to create file: " << filePath << "\n";
        exit(EXIT_FAILURE);
    }
    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
}

// Helper function to load resource data
std::vector<BYTE> LoadResourceData(DWORD& resourceSize) {
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA);
    if (!hResource) {
        std::cerr << "[error] Failed to find resource. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
    if (!hLoadedResource) {
        std::cerr << "[error] Failed to load resource. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    resourceSize = SizeofResource(NULL, hResource);
    BYTE* pResourceData = static_cast<BYTE*>(LockResource(hLoadedResource));
    if (!pResourceData) {
        std::cerr << "[error] Failed to lock resource. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    return std::vector<BYTE>(pResourceData, pResourceData + resourceSize);
}

// Function to compress data using Windows Compression API
std::vector<BYTE> CompressData(const std::vector<BYTE>& data) {
    COMPRESSOR_HANDLE compressor = NULL;
    if (!CreateCompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &compressor)) {
        std::cerr << "[error] Failed to create compressor. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    SIZE_T compressedSize = 0;

    // Determine the size needed for the compressed data
    if (!Compress(compressor, (PVOID)data.data(), data.size(), NULL, 0, &compressedSize)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            std::cerr << "[error] Failed to get compressed size. Error: " << GetLastError() << "\n";
            CloseCompressor(compressor);
            exit(EXIT_FAILURE);
        }
    }

    std::vector<BYTE> compressedData(compressedSize);

    // Compress the data
    if (!Compress(compressor, (PVOID)data.data(), data.size(), compressedData.data(), compressedSize, &compressedSize)) {
        std::cerr << "[error] Failed to compress data. Error: " << GetLastError() << "\n";
        CloseCompressor(compressor);
        exit(EXIT_FAILURE);
    }

    compressedData.resize(compressedSize);
    CloseCompressor(compressor);
    return compressedData;
}

// Encrypt data using AES
void EncryptData(HCRYPTPROV hCryptProv, HCRYPTKEY hKey, std::vector<BYTE>& data) {
    DWORD bufferSize = data.size();
    DWORD dataSize = bufferSize;

    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufferSize, 0)) {
        std::cerr << "[error] Failed to calculate buffer size for encryption. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    data.resize(bufferSize);

    if (!CryptEncrypt(hKey, 0, TRUE, 0, data.data(), &dataSize, bufferSize)) {
        std::cerr << "[error] Failed to encrypt data. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    data.resize(dataSize);
}

// Export AES key to a file
std::vector<BYTE> ExportKey(HCRYPTPROV hCryptProv, HCRYPTKEY hKey) {
    DWORD keySize = 0;
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &keySize)) {
        std::cerr << "[error] Failed to get key size. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    std::vector<BYTE> keyBlob(keySize);
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, keyBlob.data(), &keySize)) {
        std::cerr << "[error] Failed to export key. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    // Extract raw key bytes (skip the BLOBHEADER and size fields)
    const BYTE* rawKeyData = keyBlob.data() + sizeof(BLOBHEADER) + sizeof(DWORD);
    DWORD rawKeySize = keySize - (sizeof(BLOBHEADER) + sizeof(DWORD));

    return std::vector<BYTE>(rawKeyData, rawKeyData + rawKeySize);
}


int main() {
    const std::string outputFilePath = "C:\\Users\\seb\\Desktop\\encrypted_program.bin";

    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hKey = 0;

    // Acquire cryptographic context
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "[error] Failed to acquire cryptographic context. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    // Generate AES key
    if (!CryptGenKey(hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) {
        std::cerr << "[error] Failed to generate AES key. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    // Export the AES key
    std::vector<BYTE> aesKey = ExportKey(hCryptProv, hKey);

    // Load resource data
    DWORD resourceSize = 0;
    std::vector<BYTE> resourceData = LoadResourceData(resourceSize);

    // Compress the resource data
    std::vector<BYTE> compressedData = CompressData(resourceData);

    // Encrypt the compressed data
    EncryptData(hCryptProv, hKey, compressedData);

    // Combine key and encrypted data
    std::vector<BYTE> finalData;
    finalData.insert(finalData.end(), aesKey.begin(), aesKey.end());            // Append key
    finalData.insert(finalData.end(), compressedData.begin(), compressedData.end());  // Append encrypted payload

    // Write the combined data to the output file
    WriteBufferToFile(outputFilePath, finalData);

    // Clean up
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);

    std::cout << "Encryption successful. Output written to: " << outputFilePath << "\n";
    return 0;
}

