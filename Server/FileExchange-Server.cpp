/********************************************************/
/*               FILEEXCHANGE-SERVER.CPP                */
/*------------------------------------------------------*/
/*  This file contains all the code for the server app  */
/********************************************************/
#include "../common.h"

void freeServerMem(DH *dh, SSL_CTX *ctx, SSL *ssl, BIO *conn, BIO *hash, BIO *bioBuf, BIO *bRsaPrivKey, RSA *rsa){
    // This function frees all memory in use before exiting the application
    if(dh){
        DH_free(dh);
    }
    if(ctx){
        SSL_CTX_free(ctx);
    }
    if(ssl){
        SSL_clear(ssl);
        SSL_free(ssl);
    }
    if(conn){
        BIO_free(conn);
    }
    if(hash){
        BIO_free(hash);
    }
    if(bioBuf){
        BIO_free(bioBuf);
    }
    if(bRsaPrivKey){
        BIO_free(bRsaPrivKey);
    }
    if(rsa){
        RSA_free(rsa);
    }
}

int main(int argc, char *argv[]){
    DH* dh = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *conn = NULL, *hash = NULL, *bioBuf = NULL, *bRsaPrivKey = NULL, *bFile = NULL;
    RSA *rsa = NULL;
    const char *rsaPrivKeyFilename = "ServerPrivateKey.pem", *errFile = "Error 404: File not found";
    char *serverPort, fileName[FILE_NAME_LENGTH];
    int dh_err, lenRecEncChallenge, lenChallenge, lenHashChallenge, lenSignedChallenge, lenEncFileName, lenFileName, lenEncBuf, bytesRead;
    unsigned char encChallenge[BUFFER_SIZE], challenge[RND_LENGTH], hashChallenge[EVP_MAX_MD_SIZE], *signedChallenge, encFileName[BUFFER_SIZE];
    char buf[FILE_BUFFER_SIZE+1], *encBuf;
    
    if(argc < 3){
		printError("Usage: ./FileExchange-Server -port portnumber.", false);
		exit(EXIT_FAILURE);
	}
    serverPort = argv[2];
    init_OpenSSL();
    
    //-------------------------------------------------------------------------
	// 1. Wait and establish SSL connection with the client
	puts("1. Waiting for request to establish SSL connection with a client...");

    // Setup Diffie-Hellman
	dh = DH_generate_parameters(128, 5, NULL, NULL);            // Setup DH object and generate Diffie-Hellman parameters
	DH_check(dh, &dh_err);
	if(dh_err != 0){
        printError("Error generating Diffie-Hellman parameters.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
	}

    // Setup SSL context
	ctx = SSL_CTX_new(SSLv23_method());                         // Create new context compatible with generic SSL/TLS
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);             // No certificate verification...
	SSL_CTX_set_tmp_dh(ctx, dh);                                // Assign DH parameters to the context
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1){              // Set cipher list
        printError("Error setting cipher list.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
	}

    // Setup BIO
	conn = BIO_new(BIO_s_accept());
	BIO_set_accept_port(conn, serverPort);                      // Create a socket that can accept conections
	if(BIO_do_accept(conn) <= 0){                               // Bind the socket to the port serverPort
        printError("Error binding server socket.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }
    cout << "  Socket successfully binded to port " << serverPort << "! Waiting for incoming connection..." << endl;

    // Setup the SSL
	ssl = SSL_new(ctx);                                         // Create new SSL object from the context
	if(!ssl){
        printError("Error creating new SSL object from context.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, conn, conn);
	if(SSL_accept(ssl) <= 0){                                   // Accept incoming connection from client
		printError("Error accepting incoming connection from the client.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
	}
    
    // Setup the hash
    hash = BIO_new(BIO_f_md());                                 // Create new hash BIO...
    if(!hash){
        printError("Error creating hash BIO.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }
	if(!BIO_set_md(hash, EVP_sha1())){                          // ...That uses SHA1
        printError("Error setting message digest of hash to SHA1.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    bioBuf = BIO_new(BIO_s_mem());                              // Create new buffer BIO
    BIO_push(hash, bioBuf);                                     // Chain the hash and the buffer BIOs
    
    // Setup RSA
    bRsaPrivKey = BIO_new_file(rsaPrivKeyFilename, "r");        // Create BIO to read RSA public key from file
    if(!bRsaPrivKey){
        printError("Error retrieving server's private key.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }
	rsa = PEM_read_bio_RSAPrivateKey(bRsaPrivKey, NULL, NULL, NULL);// RSA structure that contains the server's public key
    if(!rsa){
        printError("Error building RSA structure.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    cout << "  Connection successfully established with client!" << endl << endl;
    
    //-------------------------------------------------------------------------
	// 2. Receive and decrypt encrypted challenge from client
	puts("2. Receiving and decrypting random challenge from client...");
    
    lenRecEncChallenge = SSL_read(ssl, encChallenge, BUFFER_SIZE);
    if(lenRecEncChallenge <= 0){                                // Receive the encrypted random challenge
        printError("Error receiving the encrypted random challenge from the client.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }                                                           
    cout << "  Encrypted random challenge received: " << buff2hex(encChallenge, lenRecEncChallenge) << "." << endl;
	lenChallenge = RSA_private_decrypt(lenRecEncChallenge, encChallenge, challenge, rsa, RSA_PKCS1_PADDING);// And decrypt it
    
    cout << "  Decrypted random challenge: " << buff2hex(challenge, lenChallenge) << "." << endl << endl;
    
    //-------------------------------------------------------------------------
	// 3. Hash the random challenge
	puts("3. Hashing the random challenge...");
    
    if(BIO_write(bioBuf, challenge, lenChallenge) <= 0){        // Write the unencrypted random challenge to the buffer BIO
        printError("Error hashing the challenge.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }
    lenHashChallenge = BIO_read(hash, hashChallenge, EVP_MAX_MD_SIZE);
    if(lenHashChallenge <= 0){                                  // Obtain a digest of the unencrypted random challenge
        printError("Error hashing the challenge.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    cout << "  Unencrypted challenge hashed: " << buff2hex(hashChallenge, lenHashChallenge) << "." << endl << endl;
    
    //-------------------------------------------------------------------------
	// 4. Sign the hash of the challenge
	puts("4. Signing the digest of the challenge...");
    
    signedChallenge = (unsigned char*)malloc(RSA_size(rsa));    // Sign the digest of the random challenge with the private key
    lenSignedChallenge = RSA_private_encrypt(lenHashChallenge, hashChallenge, signedChallenge, rsa, RSA_PKCS1_PADDING);
    
    cout << "  Digest of the challenge signed: " << buff2hex(signedChallenge, lenSignedChallenge) << "." << endl << endl;
    
    //-------------------------------------------------------------------------
	// 5. Send the signed digest back
	puts("5. Sending the signed digest of the challenge back to the client...");
    
    BIO_flush(conn);
    if(SSL_write(ssl, signedChallenge, lenSignedChallenge) <= 0){// Send signed digest to the client
        printError("Unable to send the signed digest to the client.", true);
        free(signedChallenge);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }
    free(signedChallenge);
    
    cout << "  Signed challenge sent!" << endl << endl;
    
    //-------------------------------------------------------------------------
	// 6. Receive file request from client
	puts("6. Receiving a file request from the client...");
    
    lenEncFileName = SSL_read(ssl, encFileName, BUFFER_SIZE);
    if(lenEncFileName <= 0){                                    // Receive the encrypted file request
        printError("Error receiving the file request from the client.", true);
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }                                                           // And decrypt it
	lenFileName = RSA_private_decrypt(lenEncFileName, encFileName, (unsigned char*)fileName, rsa, RSA_PKCS1_PADDING);
    
    cout << "  Received file request: '" << fileName << "'." << endl << endl;
    
    //-------------------------------------------------------------------------
	// 7. Send the file
	puts("7. Sending the file to the client...");
    
    BIO_flush(conn);
	bFile = BIO_new_file(fileName, "r");                        // Create BIO for input file
    if(!bFile){
        printError("Unable to open local file (file not found).", true);
        SSL_write(ssl, errFile, strlen(errFile)+1);             // Send error to the client and exit
          freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
		exit(EXIT_FAILURE);
    }

    encBuf = (char*)malloc(RSA_size(rsa));
    while((bytesRead = BIO_read(bFile, buf, FILE_BUFFER_SIZE)) > 0){// Read a chunk of FILE_BUFFER_SIZE characters
        buf[bytesRead] = '\0';
        cout << buf;                                            // Display it in the console
        lenEncBuf = RSA_private_encrypt(bytesRead, (unsigned char*)buf, (unsigned char*)encBuf, rsa, RSA_PKCS1_PADDING);
        SSL_write(ssl, encBuf, lenEncBuf);                      // And send the encrypted chunk to the client
    }                                                           // Repeat until done
    free(encBuf);
    
	BIO_free_all(bFile);
    cout << endl << "-- Done! File trasnfer finished! --" << endl << endl;
    
    //-------------------------------------------------------------------------
	// 8. Close the connection
	puts("8. Closing the connection...");
    
    SSL_shutdown(ssl);                                          // Close the connection
      freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, rsa);
    
    cout << "  Connection successfully closed. Goodbye!" << endl;
    
    return 0;
}
