#include <windows.h>

extern "C" void EntryPoint() {
    MessageBox(NULL, "Hello from hollowed process!", "Process Hollowing", MB_OK);
    ExitProcess(0);  // Ensure clean exit
}
