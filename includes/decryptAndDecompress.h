#ifndef DECRYPTANDDECOMPRESS_H
#define DECRYPTANDDECOMPRESS_H

#include <windows.h>
#include <wincrypt.h>
#include <compressapi.h>
#include <iostream>
#include <vector>
#include <string>

#include "Resource.h"

using namespace std;

vector<BYTE> LoadEncryptedPayload(vector<BYTE>& key);
void PrintVector(const vector<BYTE>& data, const string& description);
HCRYPTKEY ImportAESKey(HCRYPTPROV hCryptProv, const vector<BYTE>& keyData);
void DecryptData(HCRYPTKEY hKey, vector<BYTE>& data);
vector<BYTE> DecompressData(const vector<BYTE>& compressedData);

#endif  // DECRYPTANDDECOMPRESS_H