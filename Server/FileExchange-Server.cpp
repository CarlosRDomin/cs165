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
	lenDigest = BIO_gets(hash, digest, EVP_MAX_MD_SIZE);    // Obtain a digest from the hash
	BIO_push(hash, bInFile);                                //Chain on the input
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

void do_server_loop(BIO *conn){
    int err, nread;
    char buf[80];

    do{
        for(nread=0; nread<sizeof(buf); nread+=err){
            err = BIO_read(conn, buf+nread, sizeof(buf)-nread);
            if (err <= 0){
                break;
            }
        }
        
        fwrite(buf, 1, nread, stdout);
    }
    while (err > 0);
}

int main(int argc, char *argv[]){
    BIO *accept, *client;
    char *serverPort = "6001";
    
    init_OpenSSL();
    
    accept = BIO_new_accept(serverPort);    // Create a socket that can accept connections
    if(!accept){
        printError("Error creating server socket. Exiting application.");
        closeConn(accept, false);
        return -1;
    }
    if(BIO_do_accept(accept) <= 0){         // Bind the socket to the port (serverPort)
        printError("Error binding server socket. Exiting application.");
        closeConn(accept, false);
        return -1;
    }
    
    cout << "Socket successfully binded to port " << serverPort << "! Waiting for incoming connection..." << endl;
    if(BIO_do_accept(accept) <= 0){         // Block and wait until a connection is made
        printError("Error accepting connection. Exiting application.");
        closeConn(accept, false);
        return -1;
    }
        
    client = BIO_pop(accept);               // Get client BIO
    cout << "Connection successfully opened!" << endl;
    do_server_loop(client);
    closeConn(client, true);
    closeConn(accept, false);
    return 0;
}
