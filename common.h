/********************************************************/
/*                      COMMON.H                        */
/*------------------------------------------------------*/
/*  This file contains common includes and definitions  */
/********************************************************/
#ifndef COMMON_H
#define COMMON_H

#define DEBUG               1   // Set to 0 to prevent from debugging messages being printed on the console
#define RND_LENGTH          64  // Length (in bytes) of the random challenge
#define FILE_NAME_LENGTH    256 // Length (in characters) of the longest filename
#define FILE_BUFFER_SIZE    64 // Length (in characters) of the longest chunk I can read from a file
#define BUFFER_SIZE         1024// Length (in bits) of the longest chunk I can send

#include <iostream>
#include <sstream>
#include <string>
#include <stdlib.h>
using namespace std;

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>


int seedPrng(int bytes){
    // This function seeds the PRNG. Returns the number of bytes read
    return RAND_load_file("/dev/urandom", bytes);
}

void init_OpenSSL(){
    // This function initializes everything needed for a correct working of OpenSSL library
    ERR_load_crypto_strings();  // Convert error codes to readable strings
    SSL_load_error_strings();
    SSL_library_init();         // Load SSL libraries
    setbuf(stdout, NULL);       // Disable buffered output
    seedPrng(RND_LENGTH);       // Seed the PRNG
}

string buff2hex(unsigned char *buff, int len){
    // This function returns the hex representation of the first len bytes of the buffer buff
    string s = "";
    for(uint i = 0; i < len; i++)
    {
        char temp[EVP_MAX_MD_SIZE];
        sprintf(temp, "%02x", buff[i] & 0xFF);
        s += temp;
    }
    return s;
}

void printErr(const char *err){
    // This function prints the specified error string (all errors are printed with the same format)
    cout << "*** ERROR: " << err << endl;
}

bool checkErrors(){
    // This function checks whether there have been any errors with the OpenSSL library functions.
    // Prints error messages on the console (if any). Returns false if no errors occurred; true otherwise.
    bool areThereErrors = false;
    unsigned long code;
    int flags, line;
    char *data, *file, buf[256];
    stringstream sAux;

    code = ERR_get_error_line_data((const char**)&file, &line, (const char**)&data, &flags);
    while(code){                                    // Have there been any errors?
        areThereErrors = true;                      // Yes
        cout << "\t";                               // (Tabulate detailed errors)
        ERR_error_string_n(code, buf, sizeof(buf)); // Get string representation of error
        printErr(buf);                              // Print it on the console
        
        if(DEBUG){                                  // If DEBUG flag set
            sAux.str(string());
            sAux.clear();
            sAux << "(Code " << code << ") in file " << file << " line " << line << ".";
            cout << "\t";                           // (Tabulate detailed errors)
            printErr((char*)sAux.str().c_str());    // Print extended description of the error
        }
        code = ERR_get_error_line_data((const char**)&file, &line, (const char**)&data, &flags);
    }
    
    return areThereErrors;
}

void printError(const char *errMsg, bool checkErr){
    // This function prints the error message passed, and more useful data related to it if checkErr is true
    stringstream sAux;
    
    sAux << errMsg;
    if(checkErr){
        sAux << " More useful data about the failure:";
    }
    printErr((char*)sAux.str().c_str());
    
    if(checkErr){
        checkErrors();
    }
    puts("Exiting application.");
}

#endif
