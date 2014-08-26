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




int pstFunction(int tableSize, struct arpDialog* shmPtr, server2guardStruct *servers2guardConf, int arpAskersTable_tableSize, arpAsker *arpAskers_shmPtr, char *dev, int pstlRepeatLimit, int pstlPoolingTime, int pstlSleepTime){


	printf("pstFunction: me llego: tableSize: %d, shmPtr[0].ethSrcMac %s, servers2guardConf[0].ip= %s, arpAskers_tableSize= %d, arpAskers_shmPtr[0].ip=%s, dev=%s, plimit=%d, pool=%d, sleept=%d \n",tableSize, shmPtr[0].ethSrcMac, servers2guardConf[0].ip, arpAskersTable_tableSize, arpAskers_shmPtr[0].ip, dev, pstlRepeatLimit, pstlPoolingTime, pstlSleepTime);



	//ALGORITMO:
	//1|Examinar entrada por entrada de la tabla de dialogos y para cada una analizar si su destino es ESTE server2guard
	//tableSize, shmPtr[j], servers2guardConf[i] (lo mismo que la shm de s2g),arpAskersTable_tableSize, arpAskers_shmPtr[a],dev, pstlRepeatLimit,pstlPoolingTime,pstlSleepTime
	

	int j=0;
	int i=0;

	int live=1;
	int forlife=0;
	while(live==1){//podria ser un while true, se utilizo esta variable para tener condicion de corte (aunque puedo usar break...)

		sleep(5);//descanza 5 segundos antes de cada NUEVA recorrida completa

		for(j=0;j<tableSize;j++){
			printf("Comenzando el lazo por %d° vez\n",j);

			//Mostrar datos de la entrada ACUTAL segun j:

			printf("el nextState = %d\n",shmPtr[j].nextState);
			printf("el type = %d\n",shmPtr[j].type);
			printf("src: %s dst: %s\n",shmPtr[j].arpSrcIp,shmPtr[j].arpDstIp);

			//SOLO ME IMPORTAN LAS ENTRADAS CON nextState==1 PORQUE SON LAS QUE AÑADIO EL TRAFFIC COLLECTOR
			//ADEMAS, SI LA AÑADIO.. SEGURO NO ES NULL Y PUEDO ANALIZARLA TRANQUILO

			//ENTONCES SI LA TRAMA ESTA MARCADA DIFERENTE A 1 ENTONCES LA PASO POR ALTO Y VUELVE AL PRINCIPIO DEL FOR PARA ANALIZAR LA PROXIMA ENTRADA SEGUN J(J++)
			if(shmPtr[j].nextState!=1){
				printf("La entrada NO estaba marcada para checkear (%d) salto a la proxima\n",shmPtr[j].nextState);
				continue;//salto a la proxima entrada de la tabla
			}

			//SI CONTINUA ACA, SIGNIFICA QUE LA ENTRADA ESTABA MARCADA CON SU NEXTSTATE EN 1 =)

			//IGUAL ANALIZO SI NO ES RECIEN INICIALIZADA...(por comprobar no mas)
			if(shmPtr[j].type==99){//recien inicializada (ES NULL...)
				printf("<<Entrada vacia, continuar con la siguiente\n");
				continue;//salta a la proxima entrada de la tabla
			}
			else{//si no esta "vacia" (inicializada en realiadad.."
				printf("<<Esta entrada no esta vacia!!! ahora va al if de si coincide con el server que cuido...\n");
				printf("<<comparando i: %s con shmPtr: %s \n",servers2guardConf[i].ip,shmPtr[j].arpDstIp);
			}


			//SI CONTINUA ACA, SIGNIFICA QUE SE PUEDE ANALIZAR...(NO ES UNA ENTRADA RECIEN INICIALIZADA)

			//controlo el largo del srcIP como segunda medida de consistencia de la entrada (nextState no es confiable...?)
			if(7>(int)strlen(shmPtr[j].arpSrcIp)){
				printf("EPAA el largo de la srcip leido desde la tabla es menor que 7!!(no deberia mostrarse nunca\n");
				continue;//interrumpe el ciclo actual...
			}

			//SI CONTINUA ACA, SIGNIFICA QUE ESTA TODO OK EN LA ENTRADA DE LA TABLA...ES ANALIZABLE

			//AHORA ANALIZO SI ESTE SERVER2GUARD ES DESTINO DE ESTA ENTRADA DE TABLA, PARA SABER SI LA ANALIZO O NO

			printf("comparando server2guard ip: %s con shmPtr dest ip: %s \n",servers2guardConf[i].ip,shmPtr[j].arpDstIp);

			//PARA ESTA COMPARACION, PRIMERO COMPARO EL LARGO DE AMBAS, SI ES IGUAL AHI RECIEN COMPARO BYE A BYTE

			if(strlen(servers2guardConf[i].ip)!=strlen(shmPtr[j].arpDstIp)){
				printf(">> PST: NO tienen el mismo largo!! continue a la siguiente entrada...\n");
				continue;//YA SE QUE ESTE SERVER2GUARD NO ES DESTINO EN ESTA ENTRADA DE TABLA, SALTAR A LA PROXIMA ENTRADA DE TABLA, REINICIAR FOR CON J++
			}

			//EN CAMBIO SI SIGUE ACA, SIGNIFICA QUE TUVIERON EL MISMO LARGO, ASI QUE LAS COMPARO BYTE A BYTE
			printf(">> PST: SI tienen el mismo largo,es posible que esta entrada sea destinada a este server2guard\n");
			
			//COMPARAR BYE A BYTE CON STRNCMP
			if(!strncmp(servers2guardConf[i].ip,shmPtr[j].arpDstIp,strlen(shmPtr[j].arpDstIp))){
				printf(">>>PST:(eran iguales) Entrada destinada al server %s\n",(servers2guardConf[i].serverName));
				//evaluo si la entrada es pregunta o respuesta arp (solo salvo arp, y de momento solo me importan PREGUNAS porque develan intencion de dialogo)
				//La intencion de dialogo quiere decir que el que pregunta (asker) quiere comunicarse con un server (y consumir sus servicios muy probable es)

				switch(shmPtr[j].type){
					case 0:
						printf(">>ES UNA PREGUNTA ARP (INTENCION DE DIALOGO EXPRESADA)...\n");
					break;
					case 1:
						printf(">>ES UNA RESPUESTA ARP (SALTAR por ahora)\n");//NO ES PARTE DEL ALCANCE ACTUAL
						//de momento continua a la siguiente
						continue;//Esto obliga a que se continue SOLO si son preguntas ARP (obviando responses)
					break;
					default:
						printf(">>PST: ERROR: ANOMALIA EN LA ENTRADA DE LA TABLA ANALIZADA\n");
						continue;
					break;
				}//switch tipo de trama en la j entrada de la tabla

			}//IF la entrada es realmente para este server
			else{
				printf(">>>PST: Esta entrada NO es para este server, salte a la siguiente\n");
				continue;//Para que siga con la proxima entrada en la tabla
			}
			//SI no entro al else.. continua la ejecucion dado que la entrada era para el server


			int askerToLockFounded=0;//flag para saber si se podra bloquear el asker...sino lo encuentor no puedo!
			int a=0;//subindice de recorrido de askers

			//-----------------------------------------------------------------------------------------------------------------------
			//SI HIT > 1, ENTONCES SALTO (este control no ha ofrecido mucho perfomance, quiza lo elimine en proximas versiones)
			//La idea es no portstelear seguido al mismo cliente por eso el HIT...peeero no ha sido muuuy representativa la mejora

			if(shmPtr[j].hit > 2){
				printf("el HIT (%d) era mayor que 2 en el portstealer, saltando a la proxima trama..\n",shmPtr[j].hit);
				continue;//salto.. hasta que la vea el traffic de nuevo...
			}
			else{
				printf("el HIT (%d) no era mayor que 2 asi que procedo a portstelear...\n",shmPtr[j].hit);
			}
			//------------------------------------------------------------------------------------------------------------------------
				

			printf("PST: ahora busco el ASKER en la tabla para proceder...\n");

			//------------------------------------------------------------------------------------------------------------------------

			//ANTES DE BUSCAR EL ASKER.. ME FIJO QUE LA ENTRADA DE LA TABLA TENGA ASOCIACION DE ASKER
			//(tampoco ha dado mucho resultado, y basicamente era para demorar mientras el trafficCollector guardaba el asker.. pero no es necesario esto)

			printf("comprobando asociacion con asker...\n");
			for(a=0;a<10;a++){
				if(shmPtr[j].askerAssoc!=1){
					printf("NO ESTA ASOCIADA A NINGUN ASKER ESTA ENTRADA!!!\n");
					sleep(1);
				}
				else{
					printf("segun el atributo askerAssoc esta entrada cuenta con asociacion a asker\n");
					break;
				}
			}
			printf("segun las comprobaciones, esta entrada de tabla tiene askerAssoc=%d\n",shmPtr[j].askerAssoc);

			//------------------------------------------------------------------------------------------------------------------------

			//AQUI COMIENZA A RECORRER LA TABLA DE ASKERS, PARA ENCONTRAR AL SENDER DE ESTA TRAMA Y LOCKEARLO (PARA QUE NADIE MAS LO PORTSTELEE AL MISMO TIEMPO)
			//La idea de meter hilos tambien lo bueno que tiene es que cuando otro HIJO de server2gurd se bloquea esperando que se libere al asker
			//podria paraleleamente ir portsteleando otros clientes y no congelarse en esa espera como lo hace actualmente.
			//El diseño lo soporta, pero el alcance de la implementacion se ha acotado para limitar la app solo a la PoC del trabajo final.

			//RECORRER TABLA DE ASKERS

			for(a=0;a<arpAskersTable_tableSize;a++){


				//si el largo coincide comparo:
				printf("entrada askers %d\n",a);
				printf("<comparar largo de askerEntry=%s y tableEntry=%s\n",arpAskers_shmPtr[a].ip,shmPtr[j].arpSrcIp);

				//primero comparo el largo, saltando a la proxima si son distintas.

				if(strlen(arpAskers_shmPtr[a].ip)!=strlen(shmPtr[j].arpSrcIp)){
					printf("<comparacion de largo de asker antes de bloquear fallo...\n");
					continue;//continue con el siguiente asker...
				}
				//Si tuvo el mismo largo, comparar byte a byte:
				printf("mismo largo.. ahora comparar caracter a caracter...\n");
				if(!strncmp(arpAskers_shmPtr[a].ip,shmPtr[j].arpSrcIp,strlen(shmPtr[j].arpSrcIp))){
					printf("<comparacion dio igual =)\n");
					askerToLockFounded=1;//flag arriba! puedo lockearlo porque lo encontre en "a"
					//lo bloqueo y me aseguro de que sigue alli:
					sem_wait((sem_t*) & arpAskers_shmPtr[a].semaforo);
					//lo vuelvo a COMPARAR (por si justo el traffic lo modifico)
					askerToLockFounded=0;
					//RECOMPARAR:
					if(strlen(arpAskers_shmPtr[a].ip)!=strlen(shmPtr[j].arpSrcIp)){
						printf("<segunda comparacion de largo de asker antes de bloquear fallo...\n");
						//unlockeo
						sem_post((sem_t*) & arpAskers_shmPtr[a].semaforo);
						askerToLockFounded=0;//no lo encontro al final
						break;//finaliza el for sin conseguir al asker...
					}
					printf("Segunda comparacion de largo de asker coincidio nuevamente...\n");
					//comparo por strncmp
					if(!strncmp(arpAskers_shmPtr[a].ip,shmPtr[j].arpSrcIp,strlen(shmPtr[j].arpSrcIp))){
						printf("<segundo strncmp del asker coincide =)\n");
						askerToLockFounded=1;//lo usa un if luego para ejecutar el algoritmo =)
						arpAskers_shmPtr[a].status=2;//lo pongo en checking...
						break;//no sigo buscado.. me voy derecho al algoritmo =)
					}
					else{
						printf("<no coincidio en la segunda comparacion del asker.libero y cancelo\n");
						sem_post((sem_t*) & arpAskers_shmPtr[a].semaforo);
						askerToLockFounded=0;
						break;//no sigo buscando.. ya fue..
					}
				}//if del primer strncmp de asker
				else{//mismo largo, distinto asker...
					printf("<mismo largo pero el asker no era este\n");
					continue;//siga con el proximo asker
				}
			}//lazo for que busca lockear al asker...(para que nadie mas le robe el puerto!!)
			//ANALIZAR COMO HA IDO LA BUSQUEDA Y LOCK DEL ASKER:

			printf("bueno ahora me fijo si fue un fracaso la busqueda del asker o si continua...\n");

			if(askerToLockFounded==0){//evaluar si sigo con el algoritmo o salto al proximo pregunton...
				printf("<Fracaso el intento de encontrar el asker para lockearlo y portstelear,saltar!\n");
				continue;//salta al proximo
			}
			else{
				//SI entra aqui significa que lo encontro al asker, asi que puedo continuar con el portstealing =)
				printf("continuar con el algoritmo de portstealing por encontrar al asker en a=%d\n",a);
				//no hace continue.. porque sigue con ESTE mismo
			}


			//CONTINUAR CON EL ALGORITMO (implementacion de PoC de la Tesis)

			//Explicacion del loop:
			//Si bien es lo mas parecido a un while true, no es infinito.. de hecho hay un limite de veces que se repite el algoritmo
			//ESE LIMITE esta determinado por el parametro pstlRepeatLimit que indica cuantas veces como MUCHO se va a repetir el loop del while 1 == 1

			printf("<<>> Comienza el loop para portstealing...\n");
			//LOOP:
			int pst=0;//Para el algoritmo de portstealing (contador)
			int times=0;//PARA SABER CUANTAS VECES EJECUTE EL ALGORITMO Y CORTAR PARA EVITAR INANICION
			while(1==1){
				printf("Valor de times en esta vuelta: times=%d\n",times);

				printf("<<>>Dentro del while del status, comenzando el portstealing\n");
				
				//portstealing (rafaga de robo de puerto) -> Sacada del script de pruebas tester.sh
				printf("PST-MAIN: RAFAGA...\n");
				for(pst=0;pst<20;pst++){
					arper(shmPtr[j].ethSrcMac,shmPtr[j].arpSrcIp,shmPtr[j].arpDstIp,dev);
					usleep(100);
				}
//							printf("PST-MAIN: PORTSTEALING 7 SEGUNDOS....\n");
				printf("PST-MAIN: PORTSTEALING %d SEGUNDOS....\n",pstlPoolingTime);

				//portstealing (robo de tramas)
				for(pst=0;pst<pstlPoolingTime;pst++){//7 o el pstlPoolingTime es la cantidad de mensajes, pero como sin cada 1 seg .. resulta en tiempo igual :/
					arper(shmPtr[j].ethSrcMac,shmPtr[j].arpSrcIp,shmPtr[j].arpDstIp,dev);//LLAMADA OK
					printf("PST-MAIN: PORTSTEALING MESSSAGE %d\n",pst);
					usleep(1000000);
				}
				printf("PST-MAIN: DEVOLVIENDO EL PUERTO AL CLIENTE...\n");
				//Arpear por el asker (para que recupere el puerto)
				for(pst=0;pst<10;pst++){
					arper("default","default",shmPtr[j].arpSrcIp,dev);//LLAMADA OK
					usleep(100000);
				}
				printf("PST-MAIN: Algortimo completado!!!\n");

				//EVALUAR SI FUE SUFICIENTE O SI DUERMO Y SIGO...
				if(times==pstlRepeatLimit){//aqui es donde entra en juego el pstlRepeatLimit
					printf("Ya ha sido demaciado, asi que salto al proximo asker a portstelear...\n");
					break;
				}
				times++;
				//SI NO HA SIDO SUFICIENTE, CONTINUA...
				//PERO VA A DEMORAR EL SIGUIENTE CICLO, PARA NO AFECTAR PERFOMANCE DE LA RED, PARA ELLO UTILIZA pstlSleepTime

				printf("PST-MAIN: dormir antes de bombardear nuevamente...\n");

				sleep(pstlSleepTime);//este es el pstlSleepTime (10 para las prubeas en debug)

				printf("PST-MAIN: despertar al algoritmo =) \n");
			}//end while status == checking


			printf("PST-MAIN: atencion: saliendo del loop de portstealing. Se ha informado la deteccion de un SPOOFER\n");
			//END LOOP

			//--------------------------------------------------------------------------------------------------------------
			//INCREMENTAR EL HIT
			printf("valor del HIT antes: %d\n",shmPtr[j].hit);
			shmPtr[j].hit=shmPtr[j].hit + 1;//incremento el hit para no reespoofearla al vicio
			printf("incrementado el HIT para no volver a spoofear al vicio...\n");
			printf("valor del HIT luego: %d\n",shmPtr[j].hit);
			//--------------------------------------------------------------------------------------------------------------

			//FORZAR EL STATUS A CHECK PARA QUE SI OTRO PROCESO ESTABA ESPERANDO EL UNLOCK, PUEDA PROCEDER AL CHECKEAR
			arpAskers_shmPtr[a].status=2;
			//AL FINAL:::liberar:
			sem_post((sem_t*) & arpAskers_shmPtr[a].semaforo);
			printf("<liberado el semaforo del asker portsteleado\n");


			//UNA VEZ COMPROBADO ESTE ASKER, DEBERIA LIMPIAR DE LA TABLA TODOS LOS CASOS PARA ESTE ASKER
				//DE ESTE MODO LA TABLA NO SE LLENA SIEMPRE DE LO MISMO
				//TAMPOCO SUCEDE QUE SE REPITE EL PORTSTEALING EN VANO (MISMO SERVER Y MISMO CLIENTE)

			//	Y ESTE SERVER ;) (PARA OTROS SERVERS SE ENCARGAN OTROS HIJOS DEL LOOP)

			//LAZO FOR QUE RECORRE BUSCANDO COINCIDENCIAS Y ELIMINA LAS QUE SON ORIGEN EL ASKER DESTINO EL SERVER
			// LAS QUE SON INVERSAS TAMBIEN DEBERIA PORQUE NO LAS ESTOY TRATANDO DE MOMENTO.


			printf("finalizado el algoritmo, prosigo con la siguiente entrada de la tabla tabla, la vida de este for=%d\n",forlife);
			forlife++;
			
		}//CIERRO EL FOR QUE RECORRE LA TABLA PRINCIPAL DE DIALOGOS, AQUI SIGUE DENTRO DEL LOOP WHILE(LIVE==1)
		//CONTINUANDO EN EL WHILE LIVE==1...

		printf("Descanzare 5 segs y de nuevo lanzo el for...\n");
	}//CIERRO EL WHILE LIVE ==1
	return 0;
}//cierre de funcion
