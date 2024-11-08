#ifndef STARTINJECTION_H
#define STARTINJECTION_H

#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <string>

void startInjection(unsigned char data[], unsigned int data_len);


#endif  // STARTINJECTION_H

