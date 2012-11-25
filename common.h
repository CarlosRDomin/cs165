/********************************************************/
/*                      COMMON.H                        */
/*------------------------------------------------------*/
/*  This file contains common includes and definitions  */
/********************************************************/
#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

using namespace std;

ERR_load_crypto_strings();  // Convert error codes to readable strings
SSL_load_error_strings();

bool checkErrors(){
    // This function checks whether there have been any errors with the OpenSSL library functions.
    // Prints error messages on the console (if any). Returns false if no errors occurred; true otherwise.
    bool areThereErrors = false;
    int err;
    char buf[256];

    while((err = ERR_get_error()) != 0){            // Have there been any errors?
        areThereErrors = true;                      // Yes
        ERR_error_string_n(err, buf, sizeof(buf));  // Get string representation of error
        printf("*** ERROR: %s\n", buf);             // Print it on the console
    }
    
    return areThereErrors;
}

#endif
