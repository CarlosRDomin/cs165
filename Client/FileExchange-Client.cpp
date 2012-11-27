/********************************************************/
/*               FILEEXCHANGE-CLIENT.CPP                */
/*------------------------------------------------------*/
/*  This file contains all the code for the client app  */
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
	const char *rsaPubKeyFilename = "rsapublickey.pem";
	BIO *bInFile, *bOutFile, *hash;
	BIO *bRsaPrivKey, *bRsaPubKey;
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
	bRsaPubKey = BIO_new_file(rsaPubKeyFilename, "r");      // Create BIO to read RSA public key from file
	BIO_push(hash, bInFile);                                //Chain on the input
	lenDigest = BIO_gets(hash, digest, EVP_MAX_MD_SIZE);    // Obtain a digest from the hash
	rsaEnc = PEM_read_bio_RSAPrivateKey(bRsaPrivKey, NULL, NULL, NULL);
    signedDigest = (unsigned char *)malloc(RSA_size(rsaEnc));
	lenSignedDigest = RSA_private_encrypt(lenDigest, (unsigned char*)digest, signedDigest, rsaEnc, RSA_PKCS1_PADDING);
    rsaDec = PEM_read_bio_RSA_PUBKEY(bRsaPubKey, NULL, NULL, NULL);
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

void printClientError(char *errMsg, bool checkErr){
    // This function prints the error message passed, and more useful data related to it if checkErr is true
    stringstream sAux;

    sAux << errMsg;
    if(checkErrors){
        sAux << " More useful data about the failure:";
    }
    printError(sAux.str().c_str());
    
    if(checkErrors){
        checkErrors();
    }
    puts("Exiting application.");
}

int do_client_loop(SSL *ssl)
    int err, nwritten;
    char buf[80];
    
    for (;;){
        if (!fgets(buf, sizeof(buf), stdin)){
            break;
        }
        for(nwritten=0; nwritten<sizeof(buf); nwritten+=err){
            err = SSL_write(ssl, buf+nwritten, strlen(buf)-nwritten);
            if(err <= 0){
                return;
            }
        }
    }
}

int main(int argc, char *argv[]){
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *conn = NULL, *hash = NULL, *bioBuf = NULL, *bRsaPubKey = NULL;
    RSA *rsa = NULL;
    const char *rsaPubKeyFilename = "ServerPublicKey.pem";
    char *serverAddr, *serverPort, *fileName;
    stringstream connAddr;
    int lenChallenge, lenEncChallenge, lenHashSentChallenge, lenRecChallenge, lenHashRecChallenge;
    unsigned char *challenge[RND_LENGTH], *encChallenge;
    char *hashSentChallenge[EVP_MAX_MD_SIZE], *recEncChallenge[EVP_MAX_MD_SIZE], *hashRecChallenge[EVP_MAX_MD_SIZE];
    
    if(argc < 6){
		printError("Usage: ./FileExchange-Client -server serveraddress -port portnumber filename.");
        puts("Exiting application.");
		exit(EXIT_FAILURE);
	}
    serverAddr = argv[2];
    serverPort = argv[4];
    fileName = argv[5];
    connAddr << serverAddr << ":" << serverPort;
    init_OpenSSL();
    
    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	puts("1. Establishing SSL connection with the server...");
    
    // Setup SSL context:
    ctx = SSL_CTX_new(SSLv23_method());                         // Create new context compatible with generic SSL/TLS
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);             // No certificate verification...
	if(!SSL_CTX_set_cipher_list(ctx, "ADH")){                   // ...Since we are using Anonymous Diffie-Hellman key-sharing scheme
		printClientError("Error using ADH key-sharing scheme.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
	}

    // Setup BIO
    conn = BIO_new_connect((char *)connAddr.str().c_str());     // Create new BIO, setting its hostname to serverPort:serverAddr
    if(!conn){
        printClientError("Error creating connection BIO.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    // Setup the SSL
    ssl = SSL_new(ctx);                                         // Create new SSL object from the context
	if (!ssl){
        printClientError("Error creating new SSL object from context.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, conn, conn);                               // Associate conn with ssl (for both reading and writing)
	if(SSL_connect(ssl) <= 0){                                  // Connect to the server
        printClientError("Error connecting to the server (host unreachable).", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
	}
    
    // Setup the hash
    hash = BIO_new(BIO_f_md());                                 // Create new hash BIO...
    if(!hash){
        printClientError("Error creating hash BIO.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
	if(!BIO_set_md(hash, EVP_sha1())){                          // ...That uses SHA1
        printClientError("Error setting message digest of hash to SHA1.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    bioBuf = BIO_new(BIO_s_mem());                              // Create new buffer BIO
    BIO_push(hash, bioBuf);                                     // Chain the hash and the buffer BIOs
    
    bRsaPubKey = BIO_new_file(rsaPubKeyFilename, "r");          // Create BIO to read RSA public key from file
    if(!bRsaPubKey){
        printClientError("Error retrieving server's public key.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
	rsa = PEM_read_bio_RSA_PUBKEY(bRsaPubKey, NULL, NULL, NULL);// RSA structure that contains the server's public key
    if(!rsa){
        printClientError("Error building RSA structure.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }

    cout << "Connection successfully opened! Now connected to " << serverAddr << " on port " << serverPort << "." << endl;
    
    //-------------------------------------------------------------------------
	// 2. Generate a random number
	puts("2. Generating a random challenge...");
    
    lenChallenge = RND_LENGTH;
    if(!RAND_bytes(challenge, lenChallenge)){                   // Generate random challenge
        printClientError("Error generating the random challenge.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    cout << "Random challenge successfully generated: " << buff2hex(challenge, lenChallenge) << "!" << endl;
    
    //-------------------------------------------------------------------------
	// 3. Send encrypted challenge to the server 
	puts("3. Sending encrypted challenge to the server...");
    
    encChallenge = (unsigned char *)malloc(RSA_size(rsa));
	lenEncChallenge = RSA_public_encrypt(lenChallenge, challenge, encChallenge, rsa, RSA_PKCS1_PADDING);
    if(SSL_write(ssl, encChallenge, lenEncChallenge) <= 0){
        printClientError("Unable to send the encrypted random challenge.", true);
        free(encChallenge);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    free(encChallenge);
    
    cout << "\tEncrypted challenge sent: " << buff2hex(encChallenge, lenEncChallenge) << "." << endl;
    
    //-------------------------------------------------------------------------
	// 4. Hash unencrypted random challenge
	puts("4. Hashing the unencrypted random challenge...");
    
    if(BIO_write(bioBuf, challenge, lenChallenge) <= 0){        // Write the unencrypted random challenge to the buffer BIO
        printClientError("Error hashing the challenge.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    lenHashSentChallenge = BIO_gets(hash, hashSentChallenge, EVP_MAX_MD_SIZE);
    if(lenHashSentChallenge <= 0){                              // Obtain a digest of the unencrypted random challenge
        printClientError("Error hashing the challenge.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
    
    cout << "\tUnencrypted challenge hashed: " << buff2hex(hashSentChallenge, lenHashSentChallenge) << "." << endl;
    
    //-------------------------------------------------------------------------
	// 5. Receive signed hash from server and decrypt it
	puts("5. Receiving (and decrypting) signed challenge from the server...");

    lenRecChallenge = SSL_read(ssl, recEncChallenge, EVP_MAX_MD_SIZE);
    if(lenRecChallenge <= 0){                                   // Receive the encrypted signed hash of the challenge
        printClientError("Error receiving the random challenge signed from the server.", true);
        freeMem(ctx, ssl, conn, hash, bioBuf, bRsaPubKey, rsa);
		exit(EXIT_FAILURE);
    }
	lenHashRecChallenge = RSA_public_decrypt(lenRecChallenge, (unsigned char*)recEncChallenge, (unsigned char*)hashRecChallenge, rsa, RSA_PKCS1_PADDING);
    
    
    //-------------------------------------------------------------------------
	// 6. Verify server's identity
	puts("6. Verifying server's identity...");
    
    //-------------------------------------------------------------------------
	// 7. Request the file
	puts("7. Sending file request...");
    
    //-------------------------------------------------------------------------
	// 8. Receive and display the file
	puts("8. Receiving the file from the server...");
    
    
    //-------------------------------------------------------------------------
	// 9. Close the connection
	puts("9. Closing the connection...");
    
    
    
    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");
    
	//BIO_new(BIO_s_mem())
	//BIO_write
	//BIO_new_file
	//PEM_read_bio_RSA_PUBKEY
	//RSA_public_decrypt
	//BIO_free
	
	string generated_key="";
	string decrypted_key="";
    
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());
    
    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");
    
	PAUSE(2);
	//BIO_flush
    //BIO_puts
	//SSL_write
    
    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);
    
    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...");
    
    //BIO_new_file
    //SSL_read
	//BIO_write
	//BIO_free
    
	printf("FILE RECEIVED.\n");
    
    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");
    
	//SSL_shutdown
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    
    
    

    return 0;
}
