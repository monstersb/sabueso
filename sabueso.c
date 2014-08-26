/*
Silvestre Ezequiel Figueroa
FI-UM 2013
silvestrefigueroa@gmail.com

Prueba de concepto de mi tesis de ingenieria informatica (Universidad de Mendoza)
"Implementacion de un ataque port stealing para la deteccion de ataques ARP Spoofing en redes LAN"
*/


//includes del sabueso.c
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
//#include <syslog.h>

//MIS PROPIAS CABECERAS
#include "arper.h" //LO SAQUE POR DESUSO Y PARA LIMPIAR UN POCO DE CODIGO
#include "parser.h"
#include "arpDialogStruct.h"
#include "trafficCollector_callback.h"
#include "callbackArgs.h"
#include "networkSizer.h"
#include "pstFunction.h"

//MENSAJES ESTATICOS
#define MSG_START "Comienza aqui el programa principal\n"

//MACROS DE ARGS
#define TABLE_SIZE 4

//Icludes del trafficCollector.c
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>


//HANDLERS:
void sigchld_handler(int s){

	sem_t* sem;
	if((sem=sem_open("/semaforo_child", O_RDWR))==SEM_FAILED){
		perror("sem_open()");
		exit(EXIT_FAILURE);
	}
	wait(NULL);
	sem_post(sem);
}

void sigint_handler(int s){
	
	sem_unlink("/semaforo_child");
	
	//ahora hago unlink para la SharedMem

	//if((shm_unlink("/sharedMemPartida"))<0){
	int retorno = shm_unlink("/sharedMemDialogos");
	printf("retorno %d\n",retorno);
	if (retorno < 0 ) {
		perror("shm_unlink()");
		exit(EXIT_FAILURE);

	}
	retorno = shm_unlink("/sharedMemAskers");
	printf("retorno %d\n",retorno);
	if (retorno < 0 ) {
		perror("shm_unlink()");
		exit(EXIT_FAILURE);

	}
	kill(getpid(),SIGTERM);
}











//SABUESO STARTS HERE!!!


int main(int argc, char *argv[]){

	//manejador SIGTERM
	signal(SIGINT , sigint_handler);

	if(0>=write(1,MSG_START, strlen(MSG_START)))
		return -1;


	int i=0;//indice utilizando en los for...


	printf("ejecutando el parse...\n");
        sleep(1);

	//Le paso al parser una estructura server2guard para que me devuelva los parametros =)
	//EN LA IP ME VA A DEVOLVER LA NIC
	//EN EL TOS ME DEVUELVE EL SERVERQUANTITY
	//

        server2guardStruct parametersConf;//aqui voy a recibir la configuracion
//        memset(parametersConf.ip,0,sizeof(char*) * 40);
//        memset(parametersConf.mac,0,sizeof(char*) * 40);
        parametersConf.tos=0;
	parametersConf.pstlRepeatLimit=0;
	parametersConf.pstlPoolingTime=0;
	parametersConf.pstlSleepTime=0;



        if(0!=parse(argv[1],&parametersConf,0)){
		printf("Error en el archivo de configuracion\n");
		return -1;
	}

        printf("se recibio del parse: NIC: %s serversQuantity: %d\n", parametersConf.nic, parametersConf.serversQuantity);
	printf("tambien parametros del pst: pstlRepeatLimit= %d, pstlPoolingTime= %d, pstlSleepTime=%d \n", parametersConf.pstlRepeatLimit,parametersConf.pstlPoolingTime,parametersConf.pstlSleepTime);


	printf("\n\n\n");
	printf("-------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	printf("FINALIZADA LA CARGA DE PARAMETROS COMIENZA EL LANZAMIENTO DEL PROGRAMA PRINCIPAL...\n");
	printf("-------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	sleep(2);

//------------INICIA ZONA DE CONTROL DE PARAMETROS DE APLICACION-----------------------------------------------//
	//PARAMETROS DE LANZAMIENTO:

	int serversQuantity=0;
	serversQuantity = parametersConf.serversQuantity;//cantidad de servers a cuidar
	server2guardStruct servers2guardConf[serversQuantity];//creo las estructuras para los servers2guard (luego van a parar a la shm)


	//PARAMETROS DEL PORT STEALER:

	int pstlRepeatLimit=parametersConf.pstlRepeatLimit;
	int pstlPoolingTime=parametersConf.pstlPoolingTime;
	int pstlSleepTime=parametersConf.pstlSleepTime;


	//INICIALIZAR:

	for(i=0;i<serversQuantity;i++){
//		memset(servers2guardConf[i].ip,0,sizeof(char*) * 40);
//		memset(servers2guardConf[i].mac,0,sizeof(char*) * 40);
//		memset(servers2guardConf[i].serverName,0,sizeof(char*) * 30);
		servers2guardConf[i].tos=99;
	}


	parse(argv[1],&servers2guardConf,1);

	printf("\n\n\n\n\n\n\n\n\n\n\n");

	printf("Mostrando configuracion leida:\n");

	for(i=0;i<serversQuantity;i++){
		printf("server.ip: %s \n",servers2guardConf[i].ip);
		printf("server.mac: %s \n",servers2guardConf[i].mac);
		printf("server.serverName: %s \n",servers2guardConf[i].serverName);
		printf("server.tos: %d \n",servers2guardConf[i].tos);
	}


	printf("---------------------------------------------------------------\n\n");


	int j=0;//otro subindice
	int c=0;
//	int live=0;


//	serversQuantity=1;//PARA DEBUGGEAR CON UN SOLO HIJO.. SINO SE ENSUCIA MUCHISIMO EL STDOUT



	//PARAMETROS DE CAPTURA, DE PASO PREAPRA VARIABLES DE CAPTURA PARA EL PRIMER HIJO
	//COmienza a preparar la captura...
	char *dev=NULL;
	char *net=NULL;
	char *mask=NULL;
	struct in_addr addr;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;//descriptor de la captura
	struct bpf_program fp;//aca se guardara el programa compilado de filtrado
	bpf_u_int32 maskp;// mascara de subred
	bpf_u_int32 netp;// direccion de red

/*
	cdev = pcap_lookupdev(errbuf); //Buscamos un dispositivo del que comenzar la captura
	printf("\nEcontro como dispositivo %s\n",dev);
	if (dev == NULL){
		fprintf(stderr," %s\n",errbuf); exit(1);
	}
	else{
		printf("Abriendo %s en modo promiscuo\n",dev);
	}
*/

	dev = parametersConf.nic;//no utiliza la que detecta automaticamente sino que usa la de la config

	//obtener la direccion de red y la netmask de la NIC en "dev"
	if(pcap_lookupnet(dev,&netp,&maskp,errbuf)==-1){
		printf("ERROR %s\n",errbuf);
		exit(-1);
	}
	addr.s_addr = netp; //traducir direccion de red en algo legible
	if((net = inet_ntoa(addr))==NULL){
		perror("inet _ntoa");
		exit(-1);
	}
	printf("Direccion de Red: %s\n",net);
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if((net=inet_ntoa(addr))==NULL){
		perror("inet _ntoa");
		exit(-1);
	}
	printf("Mascara de Red: %s\n",mask);
	//comenzar captura y obtener descriptor llamado "descr" del tipo pcatp_t*
	descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf); //comenzar captura en modo promiscuo
	if (descr == NULL){
		printf("pcap_open_live(): %s\n",errbuf);
		exit(1);
	}


	//ahora compilo el programa de filtrado para hacer un filtro para ARP o trafico supuestamente enviado por los servers2guard
		//eso de supuestamente enviados se refiere a que me traigo las tramas que tienen ip origen la del los servers ;) asi que de ese modo
			//voy a incluir las spoofeadas y las reales para luego evaluarlas desde el trafficCollector
	//ARMAR FILTRO
	int filterLen=4095;//el tamaño del filtro se calcula segun lo que se tenga para filtrar... pasa que depende de los servers2guard seteados
	filterLen=16*serversQuantity+4;//ip+espacio de cada server mas "arp "
	char filter[filterLen];
	memset(filter,0,filterLen);//inicializo
	//ejemplo: dst host 192.168.1.1 or 192.168.1.100
	strcpy(filter,"host ");
	strcpy(filter+strlen(filter),servers2guardConf[0].ip);//a manopla para plantarle sin el | del lazo for (comodidad ??)

	for(i=1;i<serversQuantity;i++){
		strcpy(filter+strlen(filter)," or ");
		strcpy(filter+strlen(filter),servers2guardConf[i].ip);
	}

	printf("::::el filtro quedo %s y la estructura: %s \n",filter,servers2guardConf[0].ip);



	//COMPILAR FILTRO
	if(pcap_compile(descr,&fp,filter,0,netp)==-1){//luego lo cambiare para filtrar SOLO los mac2guards
		fprintf(stderr,"Error compilando el filtro\n");
		exit(1);
	}
	//Para APLICAR el filtro compilado:
	if(pcap_setfilter(descr,&fp)==-1){
		fprintf(stderr,"Error aplicando el filtro\n");
		exit(1);
	}


	//DETERMINAR EL TAMAÑO DE LA TABLA A PARTIR DE LA MASCARA DE SUBRED
	int arpAskersTable_tableSize=0;

	arpAskersTable_tableSize=networkSize(mask);//Funcion que me devulve cantidad de host segun la mascara de subred

	if(arpAskersTable_tableSize>512){
		printf("ERROR: La red es muy grande...intente con una subred mas chica\n");
                _exit(EXIT_SUCCESS);
        }

	printf("el tamaño de la red es de %d hosts \n",arpAskersTable_tableSize);
	

	--arpAskersTable_tableSize,2;//ajusto el tamaño
	//FIN PARAMETROS DE CAPTURA


	//ajuste por depuracion:
	//arpAskersTable_tableSize=10;//ESTO ES PARA DEBUG NADA MAS


//-----------FINALIZA ZONA DE CONTROL DE PARAMETROS DE APLICACION---------------------------------------------//



//------------INICIA ZONA DE DEFINICION DE ESTRUCTURAS DE DATOS DEL SABUESO--------------
	//vida de los hijos
//	int live=1;//Mas abajo se explica, es para no poner un while true.. ademas me permite INTERRUMPIR la ejecucion

	int subindexCounterId = 0;//es para indizar (o dar ID) a cada entrada de la tabla



	//-------------------------------------------------------------------------------------------------------------------------------------------

	//INICIA CREACION DE TABLA DE SERVERS2GUARD EN MEMORIA COMPARTIDA

	//Crear zona de memoria compartida para alojar la estructura (o.. array de estructuras)

	//puntero a la memoria compartida
	server2guardStruct *servers2guard_shmPtr=NULL;//le tuve que agregar Struct para mantener el array server2guard que tengo con anterioridad


	//descriptor de la memoria compartida
//	int arpAskers_fdshm;
	int servers2guard_fdshm;
	
	//sharedMem
	int servers2guardTable_tableSize=serversQuantity;//calculado dinamicamente con anterioridad ;););)
	//malloqueo para el puntero de la shm
//	arpAskers_shmPtr = (arpAsker *)malloc(sizeof(arpAsker)*arpAskersTable_tableSize);
	servers2guard_shmPtr=(server2guardStruct *)malloc(sizeof(server2guardStruct)*servers2guardTable_tableSize);

	server2guardStruct servers2guardTable[servers2guardTable_tableSize];
	//inicializacion:
	for(subindexCounterId=0;subindexCounterId<servers2guardTable_tableSize;subindexCounterId++){
		memset(servers2guardTable[subindexCounterId].mac,0,40);
		memset(servers2guardTable[subindexCounterId].ip,0,40);
		memset(servers2guardTable[subindexCounterId].serverName,0,30);
		servers2guardTable[subindexCounterId].tos=99;//Type of Service
	}//inicializadas las entradas de la tabla, paso a confeccionar la Memoria Compartida



//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
//VOY A SETEAR LA MEMORIA COMPARTIDA CON LOS MISMO DATOS QUE TENGO EN LA ESTRUCTURA (TEMPORAL, SOLO POR DEBUG, LUEGO SE GUARDARA TODO EN LA SHM DE UNA)
//Esto lo hago asi para apuntar desde el segundo fork directamente con la estructura, mientras que la shm la usan el trafficCollector y otros que precisen acceder
//Como la tabla de servers2guard es SOLO LECTURA, da igual si se leen datos de la shm o de la estructura.. en todo caso es por comodidad y debug...

	for(subindexCounterId=0;subindexCounterId<servers2guardTable_tableSize;subindexCounterId++){
                strcpy(servers2guardTable[subindexCounterId].mac,servers2guardConf[subindexCounterId].mac);
                strcpy(servers2guardTable[subindexCounterId].ip,servers2guardConf[subindexCounterId].ip);
                strcpy(servers2guardTable[subindexCounterId].serverName,servers2guardConf[subindexCounterId].serverName);
                servers2guardTable[subindexCounterId].tos=servers2guardConf[subindexCounterId].tos;//Type of Service
        }
//---------------------------------------------------------------------------------------------------------------------------------------------------------------------


	//SHAREDMEM servers2guardTable
	if(((servers2guard_fdshm=shm_open("/sharedMemServers", O_RDWR|O_CREAT, 0666))<0)){//CONSULTAR: que hace aca?!?!?!?
		perror("shm_open()");
		exit(EXIT_FAILURE);
	}
	//lo escribo en blanco
	if(!(write(servers2guard_fdshm,&servers2guardTable,sizeof(servers2guardTable)))){
	perror("write()");
	exit(EXIT_FAILURE);
	}
	//mmap:
	if(!(servers2guard_shmPtr=mmap(NULL, sizeof(server2guardStruct)*servers2guardTable_tableSize, PROT_READ|PROT_WRITE, MAP_SHARED, servers2guard_fdshm, 0))){
		perror("mmap()");
		exit(EXIT_FAILURE);
	}
	//la truncada de suerte!!:
	ftruncate(servers2guard_fdshm, sizeof(server2guardStruct)*servers2guardTable_tableSize);
	close(servers2guard_fdshm);

	//FINALIZA LA CREACION DE TABLA DE SERVERS2GUARD EN MEMORIA COMPARTIDA

	printf("me quedaron en la shm:\n");

	for(subindexCounterId=0;subindexCounterId<servers2guardTable_tableSize;subindexCounterId++){
		printf("%d ) server=%s ip=%s mac=%s\n",subindexCounterId,servers2guard_shmPtr[subindexCounterId].serverName,servers2guard_shmPtr[subindexCounterId].ip,servers2guard_shmPtr[subindexCounterId].mac);
	}
	sleep(5);


	//----------------------------------------------------------------------------------------------------------------------------------------------------------


	//INICIA CREACION DE TABLA DE DIALOGOS

	//Crear zona de memoria compartida para alojar la estructura (o.. array de estructuras)

	//puntero a la memoria compartida
	struct arpDialog* shmPtr=NULL;
	//descriptor de la memoria compartida
	int fdshm;
	//sharedMem
//	int subindexCounterId = 0;//es para indizar (o dar ID) a cada entrada de la tabla
	int tableSize=((arpAskersTable_tableSize - serversQuantity) * serversQuantity);//tabla de dialogos (preguntas ARP)
	printf("el tableSize quedo %d y nada mas que eso!\n",tableSize);
//	int tableSize=TABLE_SIZE;//POR DEBUG SE ACHICA CON LA MACRO LA TABLA (EL LAZO NO SE HACE ETERNO DE DEPURAR)
	//malloqueo para el puntero de la shm
	shmPtr = (struct arpDialog *)malloc(sizeof(struct arpDialog)*TABLE_SIZE);
	struct arpDialog arpDialoguesTable[tableSize];//CONSULTAR: AQUI NO DEBERIA MALLOQUEAR?? COREDUMP SI TABLESIZE ES MUY GRANDE!!
	//inicializacion:
	for(subindexCounterId=0;subindexCounterId<tableSize;subindexCounterId++){//ese 100 es el hardcodeado anterior
		arpDialoguesTable[subindexCounterId].arpAskerIndex=subindexCounterId;
		memset(arpDialoguesTable[subindexCounterId].ethSrcMac,0,40);
		memset(arpDialoguesTable[subindexCounterId].ethDstMac,0,40);
		memset(arpDialoguesTable[subindexCounterId].arpSrcMac,0,40);
		memset(arpDialoguesTable[subindexCounterId].arpDstMac,0,40);
		memset(arpDialoguesTable[subindexCounterId].arpSrcIp,0,40);
		memset(arpDialoguesTable[subindexCounterId].arpDstIp,0,40);
		arpDialoguesTable[subindexCounterId].type=99;//0 es pregunta, 1 es respuesta, 99 inicializada
		arpDialoguesTable[subindexCounterId].doCheckIpI=0;
		arpDialoguesTable[subindexCounterId].doCheckSpoofer=0;
		arpDialoguesTable[subindexCounterId].doCheckHosts=0;
		arpDialoguesTable[subindexCounterId].nextState=4;//POR DEFAULT SE MARCA PARA USAR
		arpDialoguesTable[subindexCounterId].askerAssoc=0;//NO ESTA ASOCIADO A NINGUN ASKER (NO SE ALMACENO EL ASKER EN LA TABLA.. TODABIA)
		arpDialoguesTable[subindexCounterId].hit=0;
		//int sem_init(sem_t *sem, int pshared, unsigned int value);
		sem_init(&(arpDialoguesTable[subindexCounterId].semaforo),1,1);//inicializa semaforos de cada entrada de la tabla
	}//inicializadas las entradas de la tabla, paso a confeccionar la Memoria Compartida

	arpDialoguesTable[4].hit=5;
	
	//SHAREDMEM arpDialoguesTableManagerArguments.h
	if(((fdshm=shm_open("/sharedMemDialogos", O_RDWR|O_CREAT, 0666))<0)){
		perror("shm_open()");
		exit(EXIT_FAILURE);
	}
	//lo escribo en blanco
	if(!(write(fdshm,&arpDialoguesTable,sizeof(arpDialoguesTable)))){
	perror("write()");
	exit(EXIT_FAILURE);
	}
	//mapear...
	if(!(shmPtr=mmap(NULL, sizeof(struct arpDialog)*tableSize, PROT_READ|PROT_WRITE, MAP_SHARED, fdshm, 0))){
		perror("mmap()");
		exit(EXIT_FAILURE);
	}
	//la truncada de suerte!!:
	ftruncate(fdshm, sizeof(struct arpDialog)*tableSize);
	close(fdshm);

	//FINALIZA CREACION DE TABLA DE DIALOGOS PARA MEMORIA COMPARTIDA

	//-------------------------------------------------------------------------------------------------------------------------------------------

	//INICIA CREACION DE TABLA DE ASKERS EN MEMORIA COMPARTIDA

	//Crear zona de memoria compartida para alojar la estructura (o.. array de estructuras)

	//puntero a la memoria compartida
	/*struct*/ arpAsker *arpAskers_shmPtr=NULL;

	//descriptor de la memoria compartida
	int arpAskers_fdshm;
	//sharedMem

//RECICLO	int subindexCounterId = 0;//es para indizar (o dar ID) a cada entrada de la tabla 

//	int arpAskersTable_tableSize=10; //lo saco del la netmask cidr obtenida al principio
	
//	arpAskersTable_tableSize=100;//hardcodeado, pero este numero se calcula a partir de la cantidad de IP usables del rango de MI netmask

	//malloqueo para el puntero de la shm
	arpAskers_shmPtr = (arpAsker *)malloc(sizeof(arpAsker)*arpAskersTable_tableSize);

	/*struct*/ arpAsker arpAskersTable[arpAskersTable_tableSize];//CONSULTAR: AQUI NO DEBERIA MALLOQUEAR?? COREDUMP SI TABLESIZE ES MUY GRANDE!!
	//inicializacion:
	for(subindexCounterId=0;subindexCounterId<arpAskersTable_tableSize;subindexCounterId++){//ese 100 es el hardcodeado anterior
		arpAskersTable[subindexCounterId].arpAskerIndex=subindexCounterId;
		memset(arpAskersTable[subindexCounterId].mac,0,40);
		memset(arpAskersTable[subindexCounterId].ip,0,40);
		arpAskersTable[subindexCounterId].status=99;
		arpAskersTable[subindexCounterId].hit=0;
		//int sem_init(sem_t *sem, int pshared, unsigned int value);
		sem_init(&(arpAskersTable[subindexCounterId].semaforo),1,1);//inicializa semaforos de cada entrada de la tabla
	}//inicializadas las entradas de la tabla, paso a confeccionar la Memoria Compartida

//	arpAskersTable[6].hit=9;//ejemplo, vamos a ver si anda la tabla.. =)
	
	//SHAREDMEM arpAskersTable
	if(((arpAskers_fdshm=shm_open("/sharedMemAskers", O_RDWR|O_CREAT, 0666))<0)){//CONSULTAR: que hace aca?!?!?!?
		perror("shm_open()");
		exit(EXIT_FAILURE);
	}
	//lo escribo en blanco
	if(!(write(arpAskers_fdshm,&arpAskersTable,sizeof(arpAskersTable)))){//podria ser el tamaño de una entrada * tarpAskersTable_ableSize como en el mmap??
	perror("write()");
	exit(EXIT_FAILURE);
	}
	//mmapear
	if(!(arpAskers_shmPtr=mmap(NULL, sizeof(arpAsker)*arpAskersTable_tableSize, PROT_READ|PROT_WRITE, MAP_SHARED, arpAskers_fdshm, 0))){
		perror("mmap()");
		exit(EXIT_FAILURE);
	}
	//la truncada de suerte!!:
	ftruncate(arpAskers_fdshm, sizeof(arpAsker)*arpAskersTable_tableSize);
	close(arpAskers_fdshm);

	//FINALIZA LA CREACION DE TABLA DE ASKERS EN MEMORIA COMPARTIDA

//------------FIN ZONA DE DEFINICION DE ESTRUCTURAS DE DATOS DEL SABUESO------------------



//------------INICIA DEFINICION DE ELEMENTOS DE IPC, CONCURRENCIA Y EXCLUSION-------------
	/*
		En este punto definire los PIPES, semaforos, etc...
		nothing to do herer for the moment...
	*/
//------------FIN DEFINICION DE ELEMENTOS DE IPC, CONCURRENCIA Y EXCLUSION----------------




//---------------INICIA FORK PARA RECOLECCION DE TRAFICO (EX ARPCOLLECTOR)----------------------------------------------------------------------------

	//ESTE HIJO ES EL QUE SE ENCARGA DE CAPTURAR TRAMAS, EVALUARLAS, ALMACENARLAS Y ADMINISTRAR ASKERS.
	//EN CASO DE DETECTARSE UNA CASO DE SPOOFING, SE ENVIARA UNA SALIDA AL SYSLOG DEL SISTEMA O PODRA AÑADIRSE FUNCIONES DE ALERTA


	switch(fork()){
		case -1:
			perror("fork()");
			_exit(EXIT_FAILURE);
		case 0:
			//Proceso trafficCollector.c
			puts("\n----------------------------");
			puts("INICIANDO TRAFFIC COLLECTOR...\n");

			//Argumentos para la funcion callback
			trafficCCArgs conf[2] = {
				{tableSize, "Argumentos",shmPtr,arpAskers_shmPtr,arpAskersTable_tableSize,servers2guard_shmPtr,servers2guardTable_tableSize}
			};
			//El bucle de captura lo armo con variables que el padre ya preparo antes cuando hizo el check de la netmask
			pcap_loop(descr,-1,(pcap_handler)trafficCollector_callback,(u_char*) conf);
			_exit(EXIT_SUCCESS);
	}//FIN DEL FORK PARA TRAFFIC ARPCOLLECTOR


//---------------FIN FORK PARA RECOLECCION DE TRAFICO (EX ARPCOLLECTOR)---------------------------------------------------------------------------------


	//Continua el padre...
	//ahora recorrer el array de servers que tengo que "cuidar" (monitorear) Y LANZAR UN HIJO PARA CADA SERVER2GUARD
	//Recordemos que cada host que tenga interes en hablar con estos servers (que tienen informacion sensible) son
	//posibles victimas de ataques arp spoofing.

	//LUEGO DESDE ESTOS HIJOS, PORTSTELEAR A LAS POSIBLES VICTIMAS (CLIENTES DEL SERVER2GUARD) Y ENCONMENDARSE AL TRAFFCICOLLECTOR PARA EL ANALISIS DE LAS TRAMAS ROBADAS





	//Ahora por cada uno de los hosts a monitorear lanzar un HIJO

	for(i=0;i<serversQuantity;i++){
		//------------INICIA FORK MULTIHILADO DE SEGUIMIENTO, ROBO DE PUERTO Y ALERTA-----------------------------
		switch(fork()){
			case -1:
				perror("fork()");
				_exit(EXIT_FAILURE);
			case 0:
				sleep(5);
				printf("INICIANDO HIJO PORT STEALER PARA EL SERVER2GUARD: %s\n",(servers2guardConf[i].serverName));
				//----------------------------------------
				while(1==1){
					sleep(1);
					
					printf("mostrando memoria compartida desde el port stealer pasada %d\n",j);
					for(c=0;c<tableSize;c++){
						printf("entrada %d  |%s  ",c,shmPtr[c].ethSrcMac);
						printf("|%s  ",shmPtr[c].ethDstMac);
						printf("|%s  ",shmPtr[c].arpSrcMac);
						printf("|%s  ",shmPtr[c].arpDstMac);
						printf("|%s  ",shmPtr[c].arpSrcIp);
						printf("|%s \n",shmPtr[c].arpDstIp);
					}
					j++;
					break;//No me iba a quedar en el while true ni loco!!! AJJajJJAAJJAaaaaa
				}
				//------------------------------------------
				//FUNCION PARA ESTE HIJO:(VER PROCEDIMIENTO DEL ALGORTIMO ALLI ADENTRO)
				printf("enviando al pstFunction: servers2guardConf[0].ip= %s pero podria enviar: %s \n",servers2guardConf[0].ip,servers2guardTable[0].ip);
				pstFunction(tableSize, shmPtr, servers2guardTable ,arpAskersTable_tableSize, arpAskers_shmPtr,dev, pstlRepeatLimit,pstlPoolingTime,pstlSleepTime);
				_exit(EXIT_SUCCESS);//del hijo de este ciclo del for

		}//CIERRO EL SWITCH FORK (tiene doble identacion del switch case fork
	}//LAZO FOR PARA LANZAR HIJOS PARA CADA SERVER QUE TENGO QUE MONITOREAR



		//------------FIN FOR DE FORKS SEGUIMIENTO, ROBO DE PUERTO Y ALERTA--------------------------------



	//UNA VEZ LANZADOS LOS HIJOS PARA CADA SERVER, CONTINUA EL PADRE...

	//FIN LABOR PADRE (si.. en general digamos)

	//fin del programa principal
	//el siguiente sleep va a cambiar por un lazo que corre durante la vida del programa... alli ya no va a haber problema de que temrine el padre..

	while(1==1){
		sleep(1);//el padre no muere.. sino me quedan los hijos ahi colgados!!
	}
	//SABUESO ENDS HERE!! (6-MAY-2013)
	write(1,"FIN DEL PROGRAMA PRINCIPAL\n",sizeof("FIN DEL PROGRAMA PRINCIPAL\n"));
	return EXIT_FAILURE;//_exit(EXIT_SUCCESS);
}//fin del programa
