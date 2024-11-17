#include "../includes/decryptAndDecompress.h"


// Helper function to load the encrypted payload from the resource
vector<BYTE> LoadEncryptedPayload(vector<BYTE>& key) {
    cout << "[debug] Loading encrypted payload from resource." << endl;
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA);
    if (hResource == NULL) {
        cerr << "[error] Failed to find payload resource." << endl;
        exit(EXIT_FAILURE);
    }

    DWORD payloadSize = SizeofResource(NULL, hResource);
    HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
    if (hLoadedResource == NULL) {
        cerr << "[error] Failed to load payload resource." << endl;
        exit(EXIT_FAILURE);
    }

    BYTE* pData = static_cast<BYTE*>(LockResource(hLoadedResource));
    if (pData == NULL) {
        cerr << "[error] Failed to lock payload resource." << endl;
        exit(EXIT_FAILURE);
    }

    vector<BYTE> data(pData, pData + payloadSize);

    if (data.size() < 32) { // AES-256 key is 32 bytes
        cerr << "[error] Encrypted payload is too small to contain key." << endl;
        exit(EXIT_FAILURE);
    }

    // Extract the first 32 bytes as the AES key
    key.assign(data.begin(), data.begin() + 32);
    vector<BYTE> encryptedData(data.begin() + 32, data.end());

    PrintVector(key, "[debug] Loaded AES key");
    PrintVector(encryptedData, "[debug] Loaded encrypted payload");

    return encryptedData;
}


// Helper function to print a vector as a hex string
void PrintVector(const vector<BYTE>& data, const string& description) {
    cout << description << " (size: " << data.size() << "): ";
    for (size_t i = 0; i < data.size() && i < 16; ++i) { // Print only the first 16 bytes
        printf("%02X ", data[i]);
    }
    if (data.size() > 16) {
        cout << "...";
    }
    cout << endl;
}



HCRYPTKEY ImportAESKey(HCRYPTPROV hCryptProv, const vector<BYTE>& keyData) {
    cout << "[debug] Importing AES key." << endl;
    HCRYPTKEY hKey = 0;
    struct {
        BLOBHEADER hdr;
        DWORD keyLength;
        BYTE keyData[32];
    } keyBlob;

    memset(&keyBlob, 0, sizeof(keyBlob));
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.keyLength = keyData.size();

    memcpy(keyBlob.keyData, keyData.data(), keyData.size());

    if (!CryptImportKey(hCryptProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
        cerr << "[error] Failed to import AES key. Error: " << GetLastError() << endl;
        exit(EXIT_FAILURE);
    }

    return hKey;
}


void DecryptData(HCRYPTKEY hKey, vector<BYTE>& data) {
    cout << "[debug] Decrypting data." << endl;
    DWORD dataSize = static_cast<DWORD>(data.size());
    if (!CryptDecrypt(hKey, 0, TRUE, 0, data.data(), &dataSize)) {
        cerr << "[error] Failed to decrypt data. Error: " << GetLastError() << endl;
        exit(EXIT_FAILURE);
    }
    data.resize(dataSize);

    PrintVector(data, "[debug] Decrypted data");
}

vector<BYTE> DecompressData(const vector<BYTE>& compressedData) {
    cout << "[debug] Decompressing data." << endl;
    DECOMPRESSOR_HANDLE decompressor = NULL;
    if (!CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &decompressor)) {
        cerr << "[error] Failed to create decompressor. Error: " << GetLastError() << endl;
        exit(EXIT_FAILURE);
    }

    SIZE_T decompressedSize = 0;
    if (!Decompress(decompressor, (PVOID)compressedData.data(), compressedData.size(), NULL, 0, &decompressedSize)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            cerr << "[error] Failed to get decompressed size. Error: " << GetLastError() << endl;
            CloseDecompressor(decompressor);
            exit(EXIT_FAILURE);
        }
    }

    vector<BYTE> decompressedData(decompressedSize);
    if (!Decompress(decompressor, (PVOID)compressedData.data(), compressedData.size(),
                    decompressedData.data(), decompressedSize, &decompressedSize)) {
        cerr << "[error] Failed to decompress data. Error: " << GetLastError() << endl;
        CloseDecompressor(decompressor);
        exit(EXIT_FAILURE);
    }

    CloseDecompressor(decompressor);

    PrintVector(decompressedData, "[debug] Decompressed data");

    return decompressedData;
}