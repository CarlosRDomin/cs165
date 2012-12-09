/********************************************************/
/*               FILEEXCHANGE-CLIENT.CPP                */
/*------------------------------------------------------*/
/*  This file contains all the code for the client app  */
/********************************************************/
#include <openssl/bio.h>
#include "../common.h"

int main(int argc, char *argv[]){
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *conn = NULL, *hash = NULL, *bioBuf = NULL, *bRsaPubKey = NULL, *bFile = NULL;
    RSA *rsa = NULL;
    const char *rsaPubKeyFilename = "ServerPublicKey.pem";
    char *serverAddr, *serverPort, *fileName;
    stringstream connAddr;
    int lenChallenge, lenEncChallenge, lenHashSentChallenge, lenRecChallenge, lenHashRecChallenge, lenEncFileName, bytesRead, lenDecBuf;
    unsigned char challenge[RND_LENGTH], *encChallenge, *encFileName;
    char hashSentChallenge[EVP_MAX_MD_SIZE], recEncChallenge[BUFFER_SIZE], hashRecChallenge[EVP_MAX_MD_SIZE], buf[BUFFER_SIZE], *decBuf;
    string hashSent, hashRec;
    
    if(argc < 6){
		printError("Usage: ./FileExchange-Client -server serveraddress -port portnumber filename.", false);
		exit(EXIT_FAILURE);
	}
    serverAddr = argv[2];
    serverPort = argv[4];
    strncpy(fileName, argv[5], FILE_NAME_LENGTH-1);             // Restrict maximum filename length 
    fileName[FILE_NAME_LENGTH-1] = '\0';                        // Ensure it is null-terminated
    connAddr << serverAddr << ":" << serverPort;
    init_OpenSSL();
    
    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	puts("1. Establishing SSL connection with the server...");
    
    // Setup SSL context
    ctx = SSL_CTX_new(SSLv23_method());                         // Create new context compatible with generic SSL/TLS
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);             // No certificate verification...
	if(!SSL_CTX_set_cipher_list(ctx, "ADH")){                   // ...Since we are using Anonymous Diffie-Hellman key-sharing scheme
		printError("Error using ADH key-sharing scheme.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
	}

    // Setup BIO
    conn = BIO_new_connect((char *)connAddr.str().c_str());     // Create new BIO, setting its hostname to serverPort:serverAddr
    if(!conn){
        printError("Error creating connection BIO.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    // Setup the SSL
    ssl = SSL_new(ctx);                                         // Create new SSL object from the context
	if (!ssl){
        printError("Error creating new SSL object from context.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, conn, conn);                               // Associate conn with ssl (for both reading and writing)
	if(SSL_connect(ssl) <= 0){                                  // Connect to the server
        printError("Error connecting to the server (host unreachable).", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
	}
    
    // Setup the hash
    hash = BIO_new(BIO_f_md());                                 // Create new hash BIO...
    if(!hash){
        printError("Error creating hash BIO.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
	if(!BIO_set_md(hash, EVP_sha1())){                          // ...That uses SHA1
        printError("Error setting message digest of hash to SHA1.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    bioBuf = BIO_new(BIO_s_mem());                              // Create new buffer BIO
    BIO_push(hash, bioBuf);                                     // Chain the hash and the buffer BIOs
    
    // Setup RSA
    bRsaPubKey = BIO_new_file(rsaPubKeyFilename, "r");          // Create BIO to read RSA public key from file
    if(!bRsaPubKey){
        printError("Error retrieving server's public key.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
	rsa = PEM_read_bio_RSA_PUBKEY(bRsaPubKey, NULL, NULL, NULL);// RSA structure that contains the server's public key
    if(!rsa){
        printError("Error building RSA structure.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }

    cout << "Connection successfully opened! Now connected to " << serverAddr << " on port " << serverPort << "." << endl;
    
    //-------------------------------------------------------------------------
	// 2. Generate a random number
	puts("2. Generating a random challenge...");
    
    lenChallenge = RND_LENGTH;
    if(!RAND_bytes(challenge, lenChallenge)){                   // Generate random challenge
        printError("Error generating the random challenge.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    cout << "Random challenge successfully generated: " << buff2hex(challenge, lenChallenge) << "!" << endl;
    
    //-------------------------------------------------------------------------
	// 3. Send encrypted challenge to the server 
	puts("3. Sending encrypted challenge to the server...");
    
    encChallenge = (unsigned char *)malloc(RSA_size(rsa));      // Encrypt the challenge
	lenEncChallenge = RSA_public_encrypt(lenChallenge, challenge, encChallenge, rsa, RSA_PKCS1_PADDING);
    BIO_flush(conn);
    if(SSL_write(ssl, encChallenge, lenEncChallenge) <= 0){     // And send it to the server
        printError("Unable to send the encrypted random challenge.", true);
        free(encChallenge);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    free(encChallenge);
    
    cout << "Encrypted challenge sent: " << buff2hex(encChallenge, lenEncChallenge) << "." << endl;
    
    //-------------------------------------------------------------------------
	// 4. Hash unencrypted random challenge
	puts("4. Hashing the unencrypted random challenge...");
    
    if(BIO_write(bioBuf, challenge, lenChallenge) <= 0){        // Write the unencrypted random challenge to the buffer BIO
        printError("Error hashing the challenge.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    lenHashSentChallenge = BIO_read(hash, hashSentChallenge, EVP_MAX_MD_SIZE);
    if(lenHashSentChallenge <= 0){                              // Obtain a digest of the unencrypted random challenge
        printError("Error hashing the challenge.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    cout << "Digest of the unencrypted challenge: " << buff2hex((unsigned char*)hashSentChallenge, lenHashSentChallenge) << "." << endl;
    
    //-------------------------------------------------------------------------
	// 5. Receive signed hash from server and decrypt it
	puts("5. Receiving (and decrypting) signed challenge from the server...");

    lenRecChallenge = SSL_read(ssl, recEncChallenge, BUFFER_SIZE);
    if(lenRecChallenge <= 0){                                   // Receive the encrypted signed hash of the challenge
        printError("Error receiving the random challenge signed from the server.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }                                                           // And decrypt it
    cout << "Received signed challenge: " << buff2hex((unsigned char*)recEncChallenge, lenRecChallenge) << "." << endl;
	lenHashRecChallenge = RSA_public_decrypt(lenRecChallenge, (unsigned char*)recEncChallenge, (unsigned char*)hashRecChallenge, rsa, RSA_PKCS1_PADDING);
    
    cout << "Decrypted digest: " << buff2hex((unsigned char*)hashRecChallenge, lenHashRecChallenge) << "." << endl;
    
    //-------------------------------------------------------------------------
	// 6. Verify server's identity
	puts("6. Verifying server's identity...");
    
    hashSent = string(hashSentChallenge);
    hashRec = string(hashRecChallenge);
    if(hashSent.compare(hashRec) != 0){                         // Check if the challenges match
        printError("Server authentication failed! Challenges sent and received don't match.", false);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    cout << "The random challenge was successfully signed by the server!" << endl;
    
    //-------------------------------------------------------------------------
	// 7. Request the file
	puts("7. Sending file request...");
    
    encFileName = (unsigned char *)malloc(RSA_size(rsa));       // Encrypt the file name
	lenEncFileName = RSA_public_encrypt(strlen(fileName) + 1, (unsigned char*)fileName, encFileName, rsa, RSA_PKCS1_PADDING);
    BIO_flush(conn);
    if(SSL_write(ssl, encFileName, lenEncFileName) <= 0){       // And send the request to the server
        printError("Unable to send the file request.", true);
        free(encFileName);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    free(encFileName);
    
    cout << "File request successfully sent: '" << fileName << "'." << endl;
    
    //-------------------------------------------------------------------------
	// 8. Receive and display the file
	puts("8. Receiving the file from the server...");
    
	bFile = BIO_new_file(fileName, "w");                        // Create BIO for output file
    if(!bFile){
        printError("Unable to create local file.", true);
        freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    decBuf = (char*)malloc(RSA_size(rsa));
    while((bytesRead = SSL_read(ssl, buf, BUFFER_SIZE)) > 0){   // Read a chunk of BUFFER_SIZE bytes
        lenDecBuf = RSA_public_decrypt(BUFFER_SIZE, (unsigned char*)buf, (unsigned char*)decBuf, rsa, RSA_PKCS1_PADDING);
        BIO_write(bFile, decBuf, lenDecBuf);                    // Encrypt and write it in the output file
        cout << decBuf;                                         // And display it also in the console
    }                                                           // Repeat until done
    free(decBuf);
	BIO_free_all(bFile);

    cout << endl << "Done! File trasnfer finished!" << endl;
    
    //-------------------------------------------------------------------------
	// 9. Close the connection
	puts("9. Closing the connection...");
    
    SSL_shutdown(ssl);                                          // Close the connection
    freeClientMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
    
    cout << "Connection successfully closed. Goodbye!" << endl;

    return 0;
}
