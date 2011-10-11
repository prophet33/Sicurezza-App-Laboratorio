#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#define bufLen 1024


 //Prova
//Stampa errore ed esce
void error (const char* msg) {
	perror(msg);
	exit(1);
}
//com di prova

int main(int argc, char * argv[])
{
//	DICHIARO LE VARIABILI
	int server, err, dim, lun;
	struct sockaddr_in server_addr;
	char buffer[bufLen];
	char *nameFile, *app, *pathFile;
	FILE* file;
	
	if (argc != 4) 
		error("Errore parametri: Specificare IP, PORTA del server e NOME FILE da trasferire");
	
	pathFile=malloc(strlen(argv[3])+1);
	strcpy(pathFile,argv[3]);
	nameFile=pathFile;
	app = strtok (nameFile,"/");
  	while (app != NULL)
  	{
		nameFile=app;
	   	app = strtok (NULL, "/");
	}
	printf("Nome File da spedire: %s\n",nameFile);
	printf("Path File da spedire: %s\n",argv[3]);
	
	file = fopen( argv[3], "rb");
	if (file == NULL) 			// IN CASO DI ERRORE
		error ("Errore apertura file");
	
//	CREO LA SOCKET
	if((server = socket(PF_INET ,SOCK_STREAM,0)) < 0) {
		error("Errore creazione Socket TCP");
	}
	
//	INERISCO NELLA STRUTTURA server_addr LE INFORMAZIONI SUL SERVER
	memset(&server_addr,0,sizeof(server_addr));
	server_addr.sin_family= AF_INET;								// TCP/IP
	server_addr.sin_port= htons((u_short)atoi(argv[2]));				// INDICO LA PORTA
	
	if(inet_pton(AF_INET, argv[1], &server_addr.sin_addr)==0) {
		error("Errore indirizzo Server");
	}
	
	printf("\n\nConnessione in corso...\n");
	
	if (connect (server, (struct sockaddr *)&server_addr, sizeof(server_addr))==-1) {
		error("Errore connessione al Server");
	}
	printf("Connessione al server %s (porta %s) effettuata con successo\n",argv[1],argv[2]);
	

	//Invio il nome del file da spedire
	lun = strlen(nameFile); 
	if((send(server, (void*)&lun, sizeof(int), 0)) == -1)
		error("Errore SEND");
	if((send(server, nameFile, lun, 0)) == -1)
		error("Errore SEND");
		
	//Invio il file
	for(;;) {
		dim=fread(buffer,1,bufLen,file);
		if (dim>0) {
			if((send(server, (void*)&dim, sizeof(int), 0)) == -1)
				error("Errore SEND");
			if((send(server, buffer, dim, 0)) == -1)
				error("Errore SEND");
		}
		if (dim<bufLen) {
			if (feof(file)) break;
			error("Errore lettura file");
		}
	}
	printf("File spedito con successo\n");

	fclose(file);
	printf("\n\n");
//	CHIUDO LA SOCKET
	close(server);
	free(pathFile);
	
	return 0;
}
