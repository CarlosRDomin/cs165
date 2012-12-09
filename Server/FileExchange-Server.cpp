/********************************************************/
/*               FILEEXCHANGE-SERVER.CPP                */
/*------------------------------------------------------*/
/*  This file contains all the code for the server app  */
/********************************************************/
#include "../common.h"

/*int main(int argc, char *argv[]){
	//This section uses BIOs to write a copy of infile.txt to outfile.txt
	//  and to send the hash of infile.txt to the command window.
	//  It is a barebones implementation with little to no error checking.
    
	//The SHA1 hash BIO is chained to the input BIO, though it could just
	//  as easily be chained to the output BIO instead.
    
	const char *inFilename = "Ruiz.txt";
	const char *outFilename = "DocOut.txt";
	const char *rsaPrivKeyFilename = "rsaprivatekey.pem";
	const char *rsaPrivKeyFilename = "rsapublickey.pem";
	BIO *bInFile, *bOutFile, *hash;
	BIO *bRsaPrivKey, *bRsaPrivKey;
	RSA *rsaEnc, *rsaDec;
	int lenDigest, lenSignedDigest, lenRecoveredDigest;
	char digest[EVP_MAX_MD_SIZE];
    unsigned char *signedDigest, *recoveredDigest;
	char* buffer[1024];
	int actualRead, actualWritten;
    
	bInFile = BIO_new_file(inFilename, "r");    // Create BIO for input file
	bOutFile = BIO_new_file(outFilename, "w");  // Create BIO for output file
	hash = BIO_new(BIO_f_md());                 // Create new hash
	BIO_set_md(hash, EVP_sha1());
	bRsaPrivKey = BIO_new_file(rsaPrivKeyFilename, "r");    // Create BIO to read RSA private key from file
	bRsaPrivKey = BIO_new_file(rsaPrivKeyFilename, "r");      // Create BIO to read RSA public key from file
	lenDigest = BIO_gets(hash, digest, EVP_MAX_MD_SIZE);    // Obtain a digest from the hash
	BIO_push(hash, bInFile);                                //Chain on the input
	rsaEnc = PEM_read_bio_RSAPrivateKey(bRsaPrivKey, NULL, NULL, NULL);
    signedDigest = (unsigned char *)malloc(RSA_size(rsaEnc));
	lenSignedDigest = RSA_private_encrypt(lenDigest, (unsigned char*)digest, signedDigest, rsaEnc, RSA_PKCS1_PADDING);
    rsaDec = PEM_read_bio_RSA_PUBKEY(bRsaPrivKey, NULL, NULL, NULL);
    recoveredDigest = (unsigned char *)malloc(RSA_size(rsaDec));
    lenRecoveredDigest = RSA_public_decrypt(lenSignedDigest, signedDigest, recoveredDigest, rsaDec, RSA_PKCS1_PADDING);
	
	while((actualRead = BIO_read(hash, buffer, 1024)) >= 1){
		actualWritten = BIO_write(bOutFile, buffer, actualRead);
	}
    
	printf("Original digest:\t");
	for(int i=0; i<lenDigest; i++){
		printf("%02x", digest[i] & 0xFF);
	}
	printf("\n");
    
    printf("Signed digest:\t\t");
	for(int i=0; i<lenSignedDigest; i++){
		printf("%02x", signedDigest[i] & 0xFF);
	}
	printf("\n");
    
    printf("Recovered digest:\t");
	for(int i=0; i<lenRecoveredDigest; i++){
		printf("%02x", recoveredDigest[i] & 0xFF);
	}
	printf("\n");
    
    free(signedDigest);
    free(recoveredDigest);
	BIO_free_all(bOutFile);
	BIO_free_all(hash);
	
	return 0;
}*/

void do_server_loop(SSL *conn){
    int err, nread;
    char buf[80];

    do{
        for(nread=0; nread<sizeof(buf); nread+=err){
            err = SSL_read(conn, buf+nread, sizeof(buf)-nread);
            if (err <= 0){
                break;
            }
        }
        
        fwrite(buf, 1, nread, stdout);
    }
    while (err > 0);
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1:0;
}

int main(int argc, char *argv[]){
    DH* dh = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *conn = NULL, *hash = NULL, *bioBuf = NULL, *bRsaPrivKey = NULL, *bFile = NULL;
    RSA *rsa = NULL;
    const char *rsaPrivKeyFilename = "ServerPrivateKey.pem", *errFile = "Error 404: File not found";
    char *serverPort, fileName[BUFFER_SIZE];
    stringstream connAddr;
    int dh_err, lenRecEncChallenge, lenChallenge, lenHashChallenge, lenSignedChallenge, lenEncFileName, lenFileName, lenEncBuf;
    unsigned char encChallenge[BUFFER_SIZE], challenge[RND_LENGTH], hashChallenge[EVP_MAX_MD_SIZE], *signedChallenge, encFileName[BUFFER_SIZE];
    char buf[BUFFER_SIZE], *encBuf;
    
    if(argc < 3){
		printError("Usage: ./FileExchange-Server -port portnumber.", false);
		exit(EXIT_FAILURE);
	}
    connAddr << "*:" << argv[2];
    serverPort = connAddr.str().c_str();
    init_OpenSSL();
    
    //-------------------------------------------------------------------------
	// 1. Wait and establish SSL connection with the client
	puts("1. Waiting for request to establish SSL connection with a client...");

    // Setup Diffie-Hellman
	dh = DH_generate_parameters(128, 5, NULL, NULL);            // Setup DH object and generate Diffie-Hellman parameters
	DH_check(dh, &dh_err);
	if(dh_err != 0){
        printError("Error generating Diffie-Hellman parameters.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
	}

    // Setup SSL context
	ctx = SSL_CTX_new(SSLv23_method());                         // Create new context compatible with generic SSL/TLS
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);             // No certificate verification...
	SSL_CTX_set_tmp_dh(ctx, dh);                                // Assign DH parameters to the context
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1){              // Set cipher list
        printError("Error setting cipher list.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
	}

    // Setup BIO
	conn = BIO_new(BIO_s_accept());
	BIO_set_accept_port(conn, serverPort);                      // Create a socket that can accept conections
	if(BIO_do_accept(conn) <= 0){                               // Bind the socket to the port serverPort
        printError("Error binding server socket. Exiting application.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }
    cout << "Socket successfully binded to port " << serverPort << "! Waiting for incoming connection..." << endl;

    // Setup the SSL
	ssl = SSL_new(ctx);                                         // Create new SSL object from the context
	if(!ssl){
        printError("Error creating new SSL object from context.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, conn, conn);
	if(SSL_accept(ssl) <= 0){                                   // Accept incoming connection from client
		printError("Error accepting incoming connection from the client.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
	}
    
    // Setup the hash
    hash = BIO_new(BIO_f_md());                                 // Create new hash BIO...
    if(!hash){
        printError("Error creating hash BIO.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }
	if(!BIO_set_md(hash, EVP_sha1())){                          // ...That uses SHA1
        printError("Error setting message digest of hash to SHA1.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }
    
    bioBuf = BIO_new(BIO_s_mem());                              // Create new buffer BIO
    BIO_push(hash, bioBuf);                                     // Chain the hash and the buffer BIOs
    
    // Setup RSA
    bRsaPrivKey = BIO_new_file(rsaPrivKeyFilename, "r");        // Create BIO to read RSA public key from file
    if(!bRsaPrivKey){
        printError("Error retrieving server's private key.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }
	rsa = PEM_read_bio_RSAPrivateKey(bRsaPrivKey, NULL, NULL, NULL);// RSA structure that contains the server's public key
    if(!rsa){
        printError("Error building RSA structure.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }
    
    cout << "Connection successfully established with client!" << endl;
    
    //-------------------------------------------------------------------------
	// 2. Receive and decrypt encrypted challenge from client
	puts("2. Receiving and decrypting random challenge from client...");
    
    lenRecEncChallenge = SSL_read(ssl, encChallenge, BUFFER_SIZE);
    if(lenRecEncChallenge <= 0){                                // Receive the encrypted random challenge
        printError("Error receiving the encrypted random challenge from the client.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }                                                           // And decrypt it
	lenChallenge = RSA_private_decrypt(lenRecEncChallenge, encChallenge, challenge, rsa, RSA_PKCS1_PADDING);
    
    cout << "\Received random challenge: " << buff2hex(challenge, RND_LENGTH) << "." << endl;
    
    //-------------------------------------------------------------------------
	// 3. Hash the random challenge
	puts("3. Hashing the random challenge...");
    
    if(BIO_write(bioBuf, challenge, lenChallenge) <= 0){        // Write the unencrypted random challenge to the buffer BIO
        printError("Error hashing the challenge.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }
    lenHashChallenge = BIO_read(hash, hashChallenge, EVP_MAX_MD_SIZE);
    if(lenHashChallenge <= 0){                                  // Obtain a digest of the unencrypted random challenge
        printError("Error hashing the challenge.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }
    
    cout << "\tUnencrypted challenge hashed: " << buff2hex(hashChallenge, lenHashChallenge) << "." << endl;
    
    //-------------------------------------------------------------------------
	// 4. Sign the hash of the challenge
	puts("4. Signing the digest of the challenge...");
    
    signedChallenge = (unsigned char*)malloc(RSA_size(rsa));    // Sign the digest of the random challenge with the private key
    lenSignedChallenge = RSA_private_encrypt(lenHashChallenge, hashChallenge, signedChallenge, rsa, RSA_PKCS1_PADDING);
    
    cout << "\tDigest of the challenge signed: " << buff2hex(signedChallenge, lenSignedChallenge) << "." << endl;
    
    //-------------------------------------------------------------------------
	// 5. Send the signed digest back
	puts("5. Sending the signed digest of the challenge back to the client...");
    
    BIO_flush();
    if(SSL_write(ssl, signedChallenge, lenSignedChallenge) <= 0){// Send signed digest to the client
        printError("Unable to send the signed digest to the client.", true);
        free(signedChallenge);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }
    free(signedChallenge);
    
    cout << "\tSigned challenge sent!" << endl;
    
    //-------------------------------------------------------------------------
	// 6. Receive file request from client
	puts("6. Receiving a file request from the client...");
    
    lenEncFileName = SSL_read(ssl, encFileName, BUFFER_SIZE);
    if(lenEncFileName <= 0){                                    // Receive the encrypted file request
        printError("Error receiving the file request from the client.", true);
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }                                                           // And decrypt it
	lenFileName = RSA_private_decrypt(lenEncFileName, encFileName, (unsigned char*)fileName, rsa, RSA_PKCS1_PADDING);
    
    cout << "\Received file request: " << fileName << "." << endl;
    
    //-------------------------------------------------------------------------
	// 7. Send the file
	puts("7. Sending the file to the client...");
    
    BIO_flush();
	bFile = BIO_new_file(fileName, "r");                        // Create BIO for input file
    if(!bFile){
        printError("Unable to open local file (file not found).", true);
        SSL_write(ssl, errFile, strlen(errFile)+1);             // Send error to the client and exit
        freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
		exit(EXIT_FAILURE);
    }

    encBuf = (char*)malloc(RSA_size(rsa));
    while((bytesRead = BIO_read(bFile, buf, BUFFER_SIZE)) > 0){ // Read a chunk of BUFFER_SIZE bytes
        lenEncBuf = RSA_private_encrypt(bytesRead, (unsigned char*)buf, (unsigned char*)encBuf, rsa, RSA_PKCS1_PADDING);
        SSL_write(ssl, encBuf, lenEncBuf);                      // Send it to the client
        cout << encBuf;                                         // And display it also in the console
    }                                                           // Repeat until done
    free(encBuf);
    
	BIO_free_all(bFile);
    cout << endl << "Done! File trasnfer finished!" << endl;
    
    //-------------------------------------------------------------------------
	// 8. Close the connection
	puts("8. Closing the connection...");
    
    SSL_shutdown(ssl);                                          // Close the connection
    freeServerMem(dh, ctx, ssl, conn, hash, bioBuf, bRsaPrivKey, bFile, rsa);
    
    cout << "Connection successfully closed. Goodbye!" << endl;
    
    return 0;
}
