#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>


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

int checkMod(const char* mod, void** mode) {

    if (strncmp(mod, "ECB",3)==0){ 
        *mode=EVP_des_ecb();
        return 0;
    }
    if (strncmp(mod, "CBC",3)==0){
        *mode=EVP_des_cbc();
        return 0;
    }
    *mode=NULL;
    return 1;
}

int main(int argc, char * argv[])
{
	int server,client, dim, lout;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int client_len = sizeof(client_addr);
	int byte, nc, ct_ptr, nctot, msg_ptr;
	int yes = 1;
    char mod[3]; //Modalita'
    char IV[DES_CBC_BLOCK_LENGTH];
	char *buffer, *digest;
	unsigned char k[DES_ECB_KEY_LENGTH], *plaintext;
	FILE *file, *file_key;
	char *alg = "sha1";
	const EVP_MD* md;
	EVP_MD_CTX* mdctx;
	void *mode=NULL;
	
	if (argc != 2)
		error("Errore parametri: Specificare PORTA di ascolto del server");
    
    
	file_key = fopen( "key.txt", "rb");
	if (file_key == NULL) 			// IN CASO DI ERRORE
		error ("Errore apertura file key");
	
	dim = fread(k,1,DES_ECB_KEY_LENGTH,file_key);
	if(dim < DES_ECB_KEY_LENGTH){
		fclose(file_key);
		error("Errore in lettura");
    }
	fclose(file_key);
	
	/* allocazione del contesto */
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
	mdctx = malloc(sizeof(EVP_MD_CTX));
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(alg);
	
	/* Inizializzazione contesto decifratura 
	EVP_CIPHER_CTX_init(ctx);
	EVP_DecryptInit(ctx, NULL, k, NULL);
	EVP_MD_CTX_init(mdctx);
	EVP_DigestInit(mdctx, md);
    */
    
    //	INSERISCO NELLA STRUTTURA server_addr LE INFORMAZIONI DEL SERVER
	memset(&server_addr,0,sizeof(server_addr));
	server_addr.sin_family = AF_INET;				// TCP/IP
	server_addr.sin_port=htons((u_short)atoi(argv[1]));	// INDICO LA PORTA
	server_addr.sin_addr.s_addr = INADDR_ANY;		// INDICO L'INDIZZO DEL SERVER INADD_ANY PER USARE TUTTI GLI INDIRIZZIDEL SERVER
	
	
    //	CREO LA SOCKET
	if((server = socket (PF_INET,SOCK_STREAM,0)) < 0)
		error("Errore creazione Socket");
    
	if(setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) 
		error("Server-setsockopt() error!");
    
    //	ASSOCIO LA SOCKET CREATA D UNA PORTA
	if (bind (server,(struct sockaddr*)&server_addr,sizeof(server_addr))<0)
		error("Errore Bind");
	
    //	SETTO LA CODA
	if(listen(server,1) == -1)
		error("Server-listen() error!");
	
    //	ATTENDO UNA CONNESSIONE
	for(;;){
		printf("\nIn attesa di una connessione...\n");
		if((client = accept (server,(struct sockaddr*) &client_addr, (socklen_t*) &client_len)) == -1) {
            error("Server-accept() error");
		}
		else { 	
			printf("Connessione stabilita con il client %s:%d on socket %d\n", inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port), client);
			
            //Ricevo la modalita'	
			if((byte = recv(client, (void *) &mod, 3, 0)) < 3) {
                if (byte!=0) {
                    perror("recv() error ");
                    continue;
                }
                printf("Disconnessione client\n");
                continue;
			} else {
                int ret=checkMod(mod,&mode);
                if((send(client, (void*)&ret, sizeof(int), 0)) == -1)
                    error("Errore SEND");
            }
            //EVP_DecryptInit(ctx, mode, k, NULL);
            
			//Ricevo il nome del file	
			if((byte = recv(client, (void *) &dim, sizeof(int), 0)) < sizeof(int)) { //Lettura dimensioni messaggio
                if (byte!=0) {
                    perror("recv() error ");
                    continue;
                }
                printf("Disconnessione client\n");
                continue;
			} 
			else {
				buffer = malloc(dim+1);
				if((byte = recv(client, buffer, dim, MSG_WAITALL)) < dim) { //Lettura dimensioni messaggio
                    free(buffer);
                    if (byte!=0) {
                        perror("recv() error ");
                        continue;
                    }
                    printf("Disconnessione client\n");
                    continue;
				}
				((char *)buffer)[dim] = '\0';
				printf("Nome File in ricezione: %s\n",(char *)buffer);
			}
            
            
			file = fopen(buffer, "wb");
			free(buffer);
			if (file == NULL) {			// IN CASO DI ERRORE
				perror ("Errore apertura file");
				exit(1);
			}
			
			/*variabili per la decifratura */
			nc = 0;
			ct_ptr = 0;	
			msg_ptr = 0;
			nctot = 0;
			digest = (char *)malloc(EVP_MD_size(md));
            
			for(;;) {
                
                EVP_CIPHER_CTX_init(ctx);
                EVP_DecryptInit(ctx, NULL, k, NULL);
                EVP_MD_CTX_init(mdctx);
                EVP_DigestInit(mdctx, md);
                
                if (strncmp(mod, "ECB", 3)==0)
                    EVP_DecryptInit(ctx, mode, k, NULL);
                
                //Ricezione IV
                if (strncmp(mod, "CBC", 3)==0) {
                    
                    if((byte = recv(client, (void *) IV, DES_CBC_BLOCK_LENGTH, 0)) <  DES_CBC_BLOCK_LENGTH) { //Lettura IV
                        if (byte != 0) {
                            perror("recv() error ");
                            break;
                        }
                        printf("Fine ricezione file\n");
                        printf("Disconnessione client\n");
                        break;
                    } else {
                        for (int i=0; i<DES_CBC_BLOCK_LENGTH; i++) {
                            printbyte(((char*)IV)[i]);
                        }
                        EVP_DecryptInit(ctx, mode, k, IV);
                    }
                    
                }
                
                
                
                if((byte = recv(client, (void *) &dim, sizeof(int), 0)) < sizeof(int)) { //Lettura dimensioni messaggio
                    if (byte != 0) {
                        perror("recv() error ");
                        break;
                    }
                    printf("Fine ricezione file\n");
                    printf("Disconnessione client\n");
                    break;
				}
				else {
					buffer = (char *)malloc(dim);
					plaintext = (unsigned char *)malloc(dim + EVP_CIPHER_CTX_block_size(ctx));
					bzero(buffer, dim);
					bzero(plaintext, dim + EVP_CIPHER_CTX_block_size(ctx));
					if((byte = recv(client, buffer, dim, MSG_WAITALL)) < dim) {
                        free(buffer);
                        free(plaintext);
                        if (byte != 0) {
                            perror("recv() error ");
                            break;
                        }
                        printf("Fine ricezione file\n");
                        printf("Disconnessione client\n");
                        break;
                    }
					
					EVP_DecryptUpdate(ctx, &plaintext[ct_ptr], &nc,(const unsigned char*) &buffer[msg_ptr], dim);
					nctot += nc;
					ct_ptr += nc;
					EVP_DecryptFinal(ctx, &plaintext[ct_ptr], &nc);
					nctot += nc;
					
					EVP_DigestUpdate(mdctx, plaintext, nctot - EVP_MD_size(md));
					EVP_DigestFinal_ex(mdctx, digest ,&lout);
					
					if( strncmp(digest, &plaintext[nctot - lout], lout) != 0 ){ // confronto tra i digest
						printf("Integrità non garantita\n");
						EVP_CIPHER_CTX_cleanup(ctx);
						EVP_MD_CTX_cleanup(mdctx);
                        free(buffer);
                        free(plaintext);
						break;
                    }
					
					byte = fwrite(plaintext, 1, nctot - lout, file);
					free(buffer);
					free(plaintext);
					if (byte < nctot - lout) {
						perror("Errore scritture file");
						exit(1);
                    }
                }
                EVP_CIPHER_CTX_cleanup(ctx);
                //EVP_CIPHER_CTX_init(ctx);
                EVP_MD_CTX_cleanup(mdctx);
                //EVP_MD_CTX_init(mdctx);
                //EVP_DecryptInit(ctx, mode, k, NULL);
                //EVP_DigestInit(mdctx, md);
                nc = 0;
                nctot = 0;
                ct_ptr = 0;
            }
            free(digest);
			printf("File ricevuto correttamente\n");
			fclose(file);
            close(client);
            
		}
	}
	
    //	CHIUDO LE SOCKET CREATE
	close(client);
	close(server);
	
	
	free(ctx);
	free(mdctx);
	return 0;
}
