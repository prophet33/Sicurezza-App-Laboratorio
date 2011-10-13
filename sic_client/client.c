#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define blockSize 1024
#define DES_ECB_KEY_LENGTH 8
#define DES_CBC_BLOCK_LENGTH 8

//Versione 1.2 con estensioni

void printbyte(char b){
	char c;
	c = b;
	c = c >> 4;
	c = c & 15;
	printf("%X:", c);
	c = b;
	c = c & 15; 
	printf("%X:", c); 
}

//Stampa errore ed esce
void error (const char* msg) {
	perror(msg);
	exit(1);
}


int main(int argc, char * argv[])
{
    //	DICHIARO LE VARIABILI
	int server, dim, lun, bufLen, lout;
	struct sockaddr_in server_addr;
	char *buffer;
	char *nameFile, *app, *pathFile;
	FILE *file, *file_key;
	unsigned char k[DES_ECB_KEY_LENGTH], *ciphertext; /* chiave di cifratura */
	int nc,	/* numero di byte [de]crittati ad ogni passo*/
    nctot, /* numero totale di byte crittati */
    ct_len, /* lunghezza del buffer */
    ct_ptr, msg_ptr; /* puntatore alla prima posizione libera del buffer */
	char* alg = "sha1";	/* algoritmo hash */
	const EVP_MD* md; /* contesto digest */
	EVP_MD_CTX* mdctx; /* contesto */
    const unsigned char* IV=NULL;
    void* mode;
    
    
    
	if (argc != 5) 
		error("Errore parametri: Specificare IP, PORTA del server, NOME FILE da trasferire, Modalita': ECB,CBC\n");
    
    if (strcmp(argv[4], "ECB")==0) {
        mode=EVP_des_ecb();
        IV=NULL;
    }
    else if (strcmp(argv[4], "CBC")==0) {
        mode=EVP_des_cbc();
        IV=malloc(DES_CBC_BLOCK_LENGTH);
        RAND_pseudo_bytes(IV, DES_CBC_BLOCK_LENGTH);
        for (int i=0; i<DES_CBC_BLOCK_LENGTH; i++) {
            printbyte(((char*)IV)[i]);
        }
    }
    else {
        printf("Modalita' errata\n");
        exit(1);
    }
        
	
	pathFile = malloc(strlen(argv[3]) + 1);
	strcpy(pathFile, argv[3]);
	nameFile = pathFile;
	app = strtok(nameFile,"/");
  	while (app != NULL){
		nameFile = app;
	   	app = strtok(NULL, "/");
    }
	printf("Nome File da spedire: %s\n",nameFile);
	printf("Path File da spedire: %s\n",argv[3]);
	
	file = fopen( argv[3], "rb");
	if (file == NULL) 			// IN CASO DI ERRORE
		error ("Errore apertura file");
	file_key = fopen( "key.txt", "rb");
	if (file_key == NULL) 			// IN CASO DI ERRORE
		error ("Errore apertura file key");
	
	dim = fread(k,1,DES_ECB_KEY_LENGTH,file_key);
	if(dim < DES_ECB_KEY_LENGTH){
		fclose(file_key);
		error("Errore in lettura");
    }
	fclose(file_key);
    
	/* allocazione dei contesti */
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
	mdctx = malloc(sizeof(EVP_MD_CTX));
	OpenSSL_add_all_digests();	/* carica tutti i digest */
	md = EVP_get_digestbyname(alg);
    
    
	/* inizializzazione dei contesti */
	EVP_CIPHER_CTX_init(ctx);
	EVP_MD_CTX_init(mdctx);
	EVP_DigestInit(mdctx, md);
	
	/*dimensione buffer considerando l'hash*/
	bufLen = blockSize + EVP_MD_size(md);
	printf("%d\n",EVP_MD_size(md));
	
	/* setup del contesto per la cifratura */
	EVP_EncryptInit(ctx, mode, k, IV);
    
	/* allocazione del buffer per ciphertext */
	ct_len = bufLen + EVP_CIPHER_CTX_block_size(ctx);
	ciphertext = (unsigned char *)malloc(ct_len);
	
	/*variabili per la cifratura*/
	nc = 0;
	nctot = 0;
	ct_ptr = 0;
	msg_ptr =0;
    
	
	/*dimensiono dinamicamente il buffer*/
	buffer = (char *)malloc(bufLen);
	
    
    
    //	CREO LA SOCKET
	if((server = socket(PF_INET ,SOCK_STREAM,0)) < 0) {
		error("Errore creazione Socket TCP");
    }
	
    //	INERISCO NELLA STRUTTURA server_addr LE INFORMAZIONI SUL SERVER
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family= AF_INET;								// TCP/IP
	server_addr.sin_port= htons((u_short)atoi(argv[2]));			// INDICO LA PORTA
	
	if(inet_pton(AF_INET, argv[1], &server_addr.sin_addr)==0) {
		error("Errore indirizzo Server");
    }
	
	printf("\n\nConnessione in corso...\n");
	
	if (connect (server, (struct sockaddr *)&server_addr, sizeof(server_addr))==-1) {
		error("Errore connessione al Server");
    }
	printf("Connessione al server %s (porta %s) effettuata con successo\n",argv[1],argv[2]);
	
    //Invio della modalita'
    if((send(server, argv[4], 3, 0)) == -1)
		error("Errore SEND");
    
    //Attendo la risposta del server
    if(recv(server, (void *) &lun, sizeof(int), 0)<=0) //Lun e' la risposta del server
        error("Errore RECV");
    
    if (lun==1) {
        printf("Il server non ha accettato la modalita'");
        exit(1);
    }
    
    
	//Invio il nome del file da spedire
	lun = strlen(nameFile); 
	if((send(server, (void*)&lun, sizeof(int), 0)) == -1)
		error("Errore SEND");
	if((send(server, nameFile, lun, 0)) == -1)
		error("Errore SEND");
    
	//Invio il file
	for(;;) {
		dim = fread(buffer,1,blockSize,file);
		if (dim > 0) {
			EVP_DigestUpdate(mdctx, buffer, dim);
			EVP_DigestFinal_ex(mdctx, &buffer[dim], &lout);
			EVP_EncryptUpdate(ctx, &ciphertext[ct_ptr], &nc, (const unsigned char *) &buffer[msg_ptr], dim + lout);
			nctot += nc;
			ct_ptr += nc;
			EVP_EncryptFinal(ctx, &ciphertext[ct_ptr], &nc);
			nctot += nc;
            
            if (IV!=NULL) {
                //Invio l'IV
                if((send(server, IV, DES_CBC_BLOCK_LENGTH, 0)) == -1)
                    error("Errore SEND");
            }
			
            
            //Invio il testo cifrato
			if((send(server, (void*)&nctot, sizeof(int), 0)) == -1)
				error("Errore SEND");
			if((send(server, ciphertext, nctot, 0)) == -1)
				error("Errore SEND");
        }
		if (dim < blockSize) {
			if (feof(file)) break;
			error("Errore lettura file");
        }
		EVP_CIPHER_CTX_cleanup(ctx);
		EVP_CIPHER_CTX_init(ctx);
		EVP_MD_CTX_cleanup(mdctx);
		EVP_MD_CTX_init(mdctx);
        if (IV!=NULL) {
            RAND_pseudo_bytes(IV, DES_CBC_BLOCK_LENGTH);
            for (int i=0; i<DES_CBC_BLOCK_LENGTH; i++) {
                printbyte(((char*)IV)[i]);
            }
        }
		EVP_EncryptInit(ctx, mode, k, IV);
		EVP_DigestInit(mdctx, md);
		nc = 0;
		nctot = 0;
		ct_ptr = 0;
    }
	printf("File spedito con successo\n");
    
	fclose(file);
	printf("\n\n");
    //	CHIUDO LA SOCKET
	close(server);
    // FREE
    if(IV!=NULL)
        free(IV);
	free(pathFile);
	free(buffer);
	free(ciphertext);
	free(ctx);
	free(mdctx);
	
	return 0;
}
