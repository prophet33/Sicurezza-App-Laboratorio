#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>



//Stampa errore ed esce
void error (const char* msg) {
	perror(msg);
	exit(1);
}

int main(int argc, char * argv[])
{
	int server,client, dim;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int client_len = sizeof(client_addr);
	int byte;
	int yes = 1;
	void* buffer;
	FILE* file;
	
	if (argc != 2)
		error("Errore parametri: Specificare PORTA di ascolto del server");

		
//	INSERISCO NELLA STRUTTURA server_addr LE INFORMAZIONI DEL SERVER
	memset(&server_addr,0,sizeof(server_addr));
	server_addr.sin_family = AF_INET;				// TCP/IP
	server_addr.sin_port=htons((u_short)atoi(argv[1]));	// INDICO LA PORTA
	server_addr.sin_addr.s_addr = INADDR_ANY;		// INDICO L'INDIZZO DEL SERVER INADD_ANY PER USARE TUTTI GLI INDIRIZZIDEL SERVER
	
	
//	CREO LA SOCKET
	if((server = socket (PF_INET,SOCK_STREAM,0)) < 0)
		error("Errore creazione Socket");

	if(setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == - 1) 
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
			
			//Ricevo il nome del file	
			if((byte=recv(client, (void *) &dim, sizeof(int), 0)) < sizeof(int)) { //Lettura dimensioni messaggio
					if (byte!=0) {
						perror("recv() error ");
						continue;
					}
					printf("Disconnessione client\n");
					continue;
			} 
			else {
				buffer=malloc(dim+1);
				if((byte=recv(client, buffer, dim, MSG_WAITALL)) < dim) { //Lettura dimensioni messaggio
						free(buffer);
						if (byte!=0) {
							perror("recv() error ");
							continue;
						}
						printf("Disconnessione client\n");
						continue;
				}
				((char *)buffer)[dim]='\0';
				printf("Nome File in ricezione: %s\n",(char *)buffer);
			}


			file = fopen(buffer, "wb");
			free(buffer);
			if (file == NULL) {			// IN CASO DI ERRORE
				perror ("Errore apertura file");
				exit(1);
			}

			for(;;) {
				 if((byte=recv(client, (void *) &dim, sizeof(int), 0)) < sizeof(int)) { //Lettura dimensioni messaggio
						if (byte!=0) {
							perror("recv() error ");
							break;
						}
						printf("Fine ricezione file\n");
						printf("Disconnessione client\n");
						break;
				}
				else {
					buffer=malloc(dim);
					if((byte=recv(client, buffer, dim, MSG_WAITALL)) < dim) {
						 	free(buffer);
							if (byte!=0) {
								perror("recv() error ");
								break;
							}
							printf("Fine ricezione file\n");
							printf("Disconnessione client\n");
							break;
					}
					byte=fwrite(buffer,1,dim,file);
					free(buffer);
					if (byte<dim) {
						perror("Errore scritture file");
						exit(1);
					}
				}
			}
			printf("File ricevuto correttamente\n");
			fclose(file);

		}
	}
	
//	CHIUDO LE SOCKET CREATE
	close(client);
	close(server);
	
	return 0;
}
