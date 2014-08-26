//Icludes del trafficCollector.c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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
#include <pthread.h>
#include <syslog.h>

//include de los semaforos:
#include <semaphore.h>

//include de la estructura de argumentos
#include "trafficCollector_callbackArguments.h"

//Include de la estructura arpDialog
#include "arpDialogStruct.h"

#define TABLE_SIZE args[0].tableSize//TAMAÑO DE LA TABLA DE DIALOGOS
#define ARPASKERS_TABLE_SIZE args[0].arpAskers_tableSize//TAMAÑO DE LA TABLA DE ASKERS

/*

	Esta funcion se encarga de 2 cosas fundamentales:
		1) monitorear trafico arp, para determinar dialogos entre equipos de la red (en caso de gratuito arp comprobar si es del atacante)
		2) validar el trafico no arp, con el objeto de comprobar un ataque MitM
			esta ultima funcionalidad se añadio a partir del renombrado de arpCollector a trafficCollecotor
			la idea es simplificar el desarrollo asumiendo el coste de perfomance y diseño


*/


//LA SIGUIENTES MACROS SON PARA EVITAR CONFUCION, DADO QUE UTILICE LAS MISMAS VARIABLES PARA REFERIRME A LA IP ORIGEN Y DESTINO EN IP Y EN ARP

#define IP_SRC "arpSrcIp"
#define IP_DST "arpDstIp"




//Callback starts here!!
void trafficCollector_callback(trafficCCArgs args[],const struct pcap_pkthdr* pkthdr,const u_char* packet){
	static int count = 1;

	//bufers para las reentrante de ether e inet
//DEBERIA UTILIZAR MEMTEST PARA INICILIZARLAS!!
	char ethSrcMacBuf[20]={};
	char ethDstMacBuf[20]={};
	char arpSrcMacBuf[20]={};
	char arpDstMacBuf[20]={};
	char arpSrcIpBuf[20]={};
	char arpDstIpBuf[20]={};

	//EN CASO DE NO SER ARP Y SER IP:
	char ipSrcBuf[20]={};
        char ipDstBuf[20]={};
	
	//los punteritos comodos ajaja
	char* ethSrcMac=NULL;
	char* ethDstMac=NULL;
	char* arpSrcMac=NULL;
	char* arpDstMac=NULL;
	char* arpSrcIp=NULL;
	char* arpDstIp=NULL;

	//EN CASO DE NO SER ARP Y SER IP:
	char* ipSrc=NULL;
        char* ipDst=NULL;

//	char *spooferDetectedMessageARP="---------------SPOOFER DETECTADO DESDE EL SABUESO: (MENSAJE ARP SPOOFEADO)!!";
//	char *spooferDetectedMessageNOARP="+++++++++++++++SPOOFER DETECTADO DESDE EL SABUESO: (TRAMAS ENVENENADAS, NO ARP)";

	int server2guardFound=0;//DEFAULT NO
	int i=0,u=0;//para lazos for, subindice
	int askerSpoofed=0,destinationSpoofed=0;
	int tableIndex=0;//para salvar el i luego cuando quiero referenciar la entrada de la tabla desde la rutina de askers
	int offset=0;//desplazamiento para aritmetica de punteros en cabecera IP

	
	//si.. muy lindo el contador.. pero me gustaria que:
		//muestre datos de la captura:
	struct ether_header* eptr;
	eptr = (struct ether_header*) packet;//apunta a la cabecera ethernet (casteado a ethernet)
	printf("-------------------------------------------------------------------------------------------------------------------\n");
	printf("Paquete numero: %d\n",count);
	count++;//lo hago aca para asegurarme que lo incrmente.. hay muchos breaks dando vueltas
	//printf("MAC origen en la TRAMA ETHERNET: %s\n", ether_ntoa(eptr−>ether_shost));
	printf("EthernetSourceMAC:             %s\n",ether_ntoa((const struct ether_addr*) eptr->ether_shost));
	//printf("MAC destino en la TRAMA ETHERNET: %s\n", ether_ntoa(eptr−>ether_dhost));
	printf("EthernetDestinationMAC:        %s\n",ether_ntoa((const struct ether_addr*) eptr->ether_dhost));

	//utiliznado las funciones reentrantes:
	ethSrcMac=ether_ntoa_r( ((const struct ether_addr*) eptr->ether_shost), ethSrcMacBuf);
	ethDstMac=ether_ntoa_r( ((const struct ether_addr*) eptr->ether_dhost), ethDstMacBuf);

	//ahora examino datos del payload de la trama ethernet (en este caso es ARP si o si por el filtro del trafficCollector)
	//compruebo que sea ARP
	if(ntohs(eptr->ether_type)!=ETHERTYPE_ARP){//NO ES ARP
		printf("====================================== NO viaja ARP sobre esta trama (SE ANALIZARA EN BUSQUEDA DE SPOOFERS...)\n");
		//aqui se trata el trafico que NO es arp

		//bueno aqui con comparar el sender de la trama con la informacion que tengo de los servers2guard me alcanza para detectar al spoofer =)
		//BUSCAR EN LA TABLA DE SERVERS2GUARD ALGUNA ENTRADA QUE TENGA IP = A LA IP DEL SENDER
		//COMPARAR LAS MAC
			//SI DA DISTINTO, ALERTAR EL SPOOFING
			//SI ES EL MISMO, PASAR POR ALTO (TRAFICO NORMAL)
		//REIRSE PORQUE ES ASI DE FACIL =)
		printf("mostrando lo que tengo en la memoria compartida...\n");
		for(i=0;i<args[0].servers2guardTable_tableSize;i++){
			printf("server=%s ip=%s mac=%s\n",args[0].servers2guard_shmPtr[i].serverName,args[0].servers2guard_shmPtr[i].ip,args[0].servers2guard_shmPtr[i].mac);
		}
//		sleep(5);
		//AHORA TENGO QUE OBTENER LA IP ORIGEN Y DESTINO DE LA CAPA DE INTERNET (IP O LAYER 3)
		if(ETHERTYPE_IP != htons(eptr->ether_type)){
			printf("Protocolo de capa de RED no soportado\n");
			return;
		}//si es que NO es IP
		//SI ES IP..continua normalemnte

		printf("tenemos cabeceras IP arriba de la trama....\n");
//		sleep(5);
		struct ip *iptr;
		offset += sizeof(struct ether_header);
		iptr = (struct ip *)(packet + offset);
		offset += sizeof(struct ip);
		printf("%s => ", inet_ntoa(iptr->ip_src));
		printf("%s\n", inet_ntoa(iptr->ip_dst));
		printf("ya mostro lo que tenia....\n");
//		sleep(10);

		//AHORA almaceno en las variables correspondientes los valores de las ip origen y destino

		 //utilizo las reentrantes:(los puse casteados a char* porque el compilador chillaba porq tenia const char*!!!!
                ipSrc=(char *)inet_ntop(AF_INET,&(iptr->ip_src), ipSrcBuf, /*INET_ADDRSTRLEN*/ sizeof ipSrcBuf );
                ipDst=(char *)inet_ntop(AF_INET,&(iptr->ip_dst), ipDstBuf, sizeof ipDstBuf );//NO ME ACUERDO BIEN EL TEMA DEL &(iptr-> cosas de tipos)
		
		
		printf(".-.-.-.-.-.-.-.-.-entonces me ha quedado: IP_SRC= %s | IP_DST= %s \n",ipSrc,ipDst);

		//UNA VEZ QUE TENGO LAS IP Y LAS MAC, PROCEDO A BUSCAR EN LA TABLA DE SERVERS LA IP Y SI LA ENCUENTRO COMPROBAR LA COINCIDENCIA DE LAS MAC
		printf("buscando IP extraida en la tabla de servers...\n");		
		server2guardFound=0;//no encontrado por default
		for(i=0;i<args[0].servers2guardTable_tableSize;i++){
			//COMPARAR EL LARGO PRIMERO
			printf("comparando: Leida: %s Capturada: %s \n",args[0].servers2guard_shmPtr[i].ip,ipSrc);
			if(strlen(args[0].servers2guard_shmPtr[i].ip)!=strlen(ipSrc)){
				printf("la ip tiene distinto largo\n");
				continue;//salto a la proxima entrada de la tabla
			}//si no coincide el largo
			else{//mismo largo...
				printf("tienen el mismo largo...paso a compararlas completamente...\n");
				if(!strncmp(args[0].servers2guard_shmPtr[i].ip,ipSrc,strlen(ipSrc))){
					printf("Se encontro coincidencias en IP leida=%s y extraida=%s en %d\n",args[0].servers2guard_shmPtr[i].ip,ipSrc,i);
					server2guardFound=1;//se encontro un server coincidente con el sender!!
					break;//rompo el lazo y continua adelante del lazo (me quedo i con el subindex del server;)
				}
				else{//Distintos
					printf("tenia el mismo largo pero la ip extraida no era la misma que el server leido en %d \n",i);
				}
			}//cierro else que entra si tienen el mismo largo

                }//continua aqui por el break
		printf("fuera del for, evaluo si se encontro o no al SRC en la lista de servers2guard\n");
		if(server2guardFound==0){//no se encontro el server y se termino el lazo
			printf("host origen %s no coincidio con ningun server monitoreado\n",ipSrc);
			return;
		}
		//SINO..CONTINUA AQUI :=)
		printf("El host origen %s coincidio con el server monitoreado %s\n",args[0].servers2guard_shmPtr[i].ip,ipSrc);
		//comparo las MAC address:
		printf("comparando MAC capturada= %s contra MAC del server2guard= %s\n",ethSrcMac,args[0].servers2guard_shmPtr[i].mac);
		


		if(strlen(ethSrcMac)!=strlen(args[0].servers2guard_shmPtr[i].mac)){
			printf("SPD: SPOOFER NO ARP DETECTADO!! LAS MAC NO COINCIDEN EN LARGO...\n");

			//syslog(1, "%s", spooferDetectedMessageNOARP);

			char *syslogAlert = NULL;
                        syslogAlert="SPOOFER DETECTADO! DATAGRAMA:";
			syslog(1,"%s SRC: %s (%s) %s -> DST: %s %s", syslogAlert,ethSrcMac,args[0].servers2guard_shmPtr[i].mac,ipSrc,ethDstMac,ipDst);

			
			//return;//ANtes de retornar debo indicar que el asker status es 1, para ello me espero y hago el return mas a bajo
			askerSpoofed=1;//indicar que el asker se detecto como spoofeado
		}
		else{//sino, si tienen el mismo largo las comparo caracter a caracter
			if(!strncmp(ethSrcMac,args[0].servers2guard_shmPtr[i].mac,strlen(args[0].servers2guard_shmPtr[i].mac))){
				printf("TRANQUILO, LAS MACS NO ARP SON IGUALES, LA TRAMA ES CONFIABLE...\n");
				return;
			}
			else{//no coinciden
				printf("SPD: SPOOFER NO ARP DETECTADO POR SER DISTINTAS LAS MACS A PESAR DE TENER EL MISMO LARGO!!!!!!\n");
				//syslog(1, "%s", spooferDetectedMessageNOARP);
				char *syslogAlert = NULL;
	                        syslogAlert="SPOOFER DETECTADO! DATAGRAMA:";
        	                syslog(1,"%s SRC: %s (%s) %s -> DST: %s %s", syslogAlert,ethSrcMac,args[0].servers2guard_shmPtr[i].mac,ipSrc,ethDstMac,ipDst);

				//return;//return;//ANtes de retornar debo indicar que el asker status es 1, para ello me espero y hago el return mas a bajo
				askerSpoofed=1;//indicar que el asker se detecto como spoofeado
			}
		}
		//EN AMBOS CASOS DE DETECCION DE SPOOFER... SE CONTINUA LA EJECUCION AQUI, LUEGO HE DE MARCAR AL ASKER COMO SPOOFEADO:
		if(askerSpoofed==1){
			//BUSCAR AL ASKER:(RECORRER TABLA DE ASKERS)
			for(u=0;u<ARPASKERS_TABLE_SIZE;u++){
				printf("buscando %s en la tabla de askers\n",ipSrc);//busco la IP origen en la tabla de askers

				//chequear si coincide
				//1| si la entrada esta en NULL entonces esta vacia, saltar a la siguiente
				if(args[0].arpAskers_shmPtr[u].status==99){//status 99 es inicializado asi que es el "null" en este caso..
					printf("entrada vacia, saltar a la proxima porque estoy comparando nada mas...\n");
					continue;//continue salta al proximo ciclo.. break rompe el lazo y return la instancia..
				}
				else{//si entra aca hay algo en la entrada..compararlo entonces con la arpSrcIp que tengo
					printf("comparando: %s contra %s por no estar vacia la entrada\n", args[0].arpAskers_shmPtr[u].ip,ipSrc);
					//OJO que tengo que ver que tengan el mismo strlen para asegurarme de que puedo hacer la comparacion strncmp
					//sino, por ejemplo si comparo 1.1.1.111 con 1.1.1.1 con strlen(1.1.1.1) me van a dar iguales!!!
					if(strlen(ipSrc)!=strlen(args[0].arpAskers_shmPtr[u].ip)){
						printf("tienen diferente largo.. asi que son diferentes.. no comparo nada sin distitnas y punto\n");
						continue;//saltar a la proxima entrada de asker.. proximo ciclo de ESTE for
					}
					//Else continua ejecutando aqui porque no hizo el continue del IF =^.^=
					printf("tienen el mismo largo, pueden ser iguales, asi que las comparo...\n");
					//como se que si sigo aqui es porque tienen el MISMO largo, entonces comparo por strNcmp...
					if(!strncmp(args[0].arpAskers_shmPtr[u].ip,ipSrc,strlen(ipSrc))){
						//SI SON IGUALES, ES PORQUE TENGO AL ASKER, LO MARCO!!
						printf("SI: %s == %s => Lo marco para que no lo portsteleenmas\n",ipSrc,args[0].arpAskers_shmPtr[u].ip);
						//MARCAR EL ASKER (como spoofeado, luego al romperse el while en el sabueso(fork 2) volerlo a check
							//Eso de volverlo a check es porque si otro hijo estaba esperando que se unlockeara para
							//chekearlo, debera poder entrar al su while sino nunca va a entrar y nadie mas podria checkearlo

						args[0].arpAskers_shmPtr[u].status=1;//spoofed (si, lo hace sin semaforo... asi de tenaz no mas!!	
						//HACER EL RETURN QUE LE COMENTE DEBAJO DE SYSLOG A LOS IF'S ANTERIORES
						return;

					}
					else{
						printf("al final eran diferentes, asi que paso a la siguiente a ver si encuentro el asker y lo marco\n");
					}
				}//else porque status!=99
			}//for u=0 para askers
		}//if spoofed == 1
	
	}//cierro el if "si NO es ARP"...
	else{//ES ARP
		printf("++++++++++++++++++++++++++++++++++++++TENEMOS ARP sobre esta trama\n");

		//aqui se trata el trafico que SI es arp (preguntas y respuestas para dialogos como para deteccion de spoofer (esto ultimo no implentado aun)
		struct ether_arp *arpPtr;
		//ahora posiciono el puntero en el primer byte(es decir con un offset de size of ether header)
		arpPtr =(struct ether_arp*)(packet+sizeof(struct ether_header));//o lo que es lo mismo packet+14;
		//ahorita, muestro la info que tiene la estructura esta para ARP:
//		fprintf(stdout,"ARP: IP Origen: %d.%d.%d.%d\n",arpPtr->arp_spa[0],arpPtr->arp_spa[1],arpPtr->arp_spa[2],arpPtr->arp_spa[3]);
		fprintf(stdout,"ARP: IP ORIGEN:  %s\n",inet_ntoa(*(struct in_addr *) arpPtr->arp_spa));
//		fprintf(stdout,"ARP: IP Destino: %d.%d.%d.%d\n",arpPtr->arp_tpa[0],arpPtr->arp_tpa[1],arpPtr->arp_tpa[2],arpPtr->arp_tpa[3]);
		fprintf(stdout,"ARP: IP DESTINO: %s\n",inet_ntoa(*(struct in_addr *) arpPtr->arp_tpa));

		//ahora utilizo las reentrantes:(los puse casteados a char* porque el compilador chillaba porq tenia const char*!!!!
		arpSrcIp=(char *)inet_ntop(AF_INET,arpPtr->arp_spa, arpSrcIpBuf, /*INET_ADDRSTRLEN*/ sizeof arpSrcIpBuf );
		arpDstIp=(char *)inet_ntop(AF_INET,arpPtr->arp_tpa, arpDstIpBuf, sizeof arpDstIpBuf );


		printf("ARP: MAC Origen:               %s\n",ether_ntoa((const struct ether_addr*) arpPtr->arp_sha));
		printf("ARP: MAC Destino:              %s\n",ether_ntoa((const struct ether_addr*) arpPtr->arp_tha));

		//Ahora muestro si es pregunta o respuesta ARP:
		switch(arpPtr->arp_op/256){
			case ARPOP_REQUEST:
				printf("Es una Consulta ARP\n");
			break;
			case ARPOP_REPLY:
				printf("Es una Respuesta ARP\n");
			break;
			default:
				printf("Caso anomalo ARP, o bien mensjae RARP\n");
			break;
		}

		//utilizando las reentrantes:		
		arpSrcMac=ether_ntoa_r( ((const struct ether_addr*) arpPtr->arp_sha), arpSrcMacBuf);
		arpDstMac=ether_ntoa_r( ((const struct ether_addr*) arpPtr->arp_tha), arpDstMacBuf);

//		printf("hasta ahora tengo: \n %s\n %s\n %s\n %s\n %s\n %s\n",ethSrcMac,ethDstMac,arpSrcMac,arpDstMac,arpSrcIp,arpDstIp);

		printf("-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n");
		int srcMacEquals=1;//coinciden por default
		char* broadcastMac="ff:ff:ff:ff:ff:ff";//Estara mal? deberia inicializar a null y luego cargarle la cadena?deberia reservar?
		char* zeroMac="0:0:0:0:0:0";//lo mismo que el anterior
		int doCheckIpI=0;
		int doCheckSpoofer=0;
		int doCheckWAck=0;
		int arpType=2;//0 es pregunta, 1 es respuesta, 2 es inicializado
	//	int doHitIncrement=0;
		int nextState=0;//por default, almacenarla y ya
		int type=99;//consultar posibles valores en tabla_de_dialogos.txt [Arquitectura] (lo uso para saber si esta inicializada, vacia)
//		int i=0;
	//	int dstZeroMacFlag=0;
	//	int dstBrdMacFlag=0;
		int askFlag=0;
		int dropFlag=0;
		int comparacion=11;//el numero minimo de elementos de una mac segun pcap =) (lo uso en los for..un capricho)
		int savedFlag=0;//se utiliza para saber si se almacenaron o no los datos... en el for de almacenamiento..
		int writableFlag=0;



		//Ahora como minimo reviso consistencias menores en la trama y el mensaje ARP
		//Si es una pregunta ARP de configuracion (cuando levanta la interfaz pregunta por si mismo) hago DROP de una
		if(! (strcmp(arpSrcIp,"0.0.0.0")) ){
			printf("MENSAJE DE AUTOCONFIGURACION, DROPEAR SIN ANALIZAR\n");
			return;

		}
	
		//SIN NO ES ESE TIPO DE MENSAJE.. CONTINUAR NORMALMENTE...


		if(strncmp(ethSrcMac,arpSrcMac,strlen(arpSrcMac))){
			printf("LOG:se ha detectado inconsistencia entre la MAC origen de la trama y la MAC origen del mensaje ARP\n");
			//podria haber sido proxyARP???
			printf("LOG:Son realmente distintos %s y %s  ??\n",ethSrcMac,arpSrcMac);
			//desde ya establezco que la trama es inconsistente en la direccion MAC de origen
			srcMacEquals=0;//ya que por default coinciden...
		}
		else{//si en lugar de no coincidir, viene como es esperable...
			printf("LOG:ethSrcMac=arpSrcMac     OK\n");
			srcMacEquals=1;//aunque por default coinciden
		}
		//Las comparaciones para determinar si es una pregunta pueden omitirse si consulto el tipo de msj arp de la estructura provista por pcap...de
		if(strcmp(ethDstMac,arpDstMac)){
			printf("LOG: las mac destino son DISTINTAS por strcmp\n");
			//codigo para cuando son distintas aqui...
			if(!strcmp(ethDstMac,broadcastMac)){
//				dstBrdMacFlag=1;
				puts("LOG:ethDsrMac es broadcast por strcmp!!!\n");
				//mmm iba al broadcast, sera una pregunta realmente? o sera para engañar?
				if(!strcmp(arpDstMac,zeroMac)){//si devuelve 0 son iguales :)
					//si es una pregunta ARP, lo marco para consultar su credibilidad? o consulto yo en db conocimiento?
					//OK, tiene la arquitectura de ARP request/question
					//es al menos una trama aceptable, podria verificarse luego pero al menos la guardo
					//verifico si la IP de destino coincide con la del host que tiene la MAC ethDstMac en dbconocimiento
					//si quiero realmente probar esto, deberia chequear los pares MACIP de cada host participante
//					dstZeroMacFlag=1;
					printf("LOG:puede que sea una pregunta ARP legitima..\n");//faltaria verificar match de ip-mac origen.
					//bien, esta trama esta marcada para verificarse integridad IP, luego steal en busqueda de spoofers
					doCheckIpI=1;
					doCheckSpoofer=1;
					nextState=1;
					askFlag=1;//porque supongo es pregunta ARP (se usa en el programa como flag)
					type=0;//campo que indica que se trata de una pregunta (se usa en la trama no en el programa como flag)
					printf("Finalizada la evaluacion, continua con la carga de datos...\n");
				}
				else{//Si entra aqui, es porque fue al broadcast, pero el ARP tiene un destino FIJO, es muy extraño!!
					printf("LOG:caso extraño, ethDstMac broadcast y arpDstMac Unicast...anomalo!!\n\n");
					//podria verificar el match IP-MAC origen, es un caso para WARN no para evaluarlo 
					//He decidido activar el flag type en WARN y no tratar el problema pero si mostrarlo!!
//					type="WARN";//deberian ser un macro de variable entero y ya..
					
				}
			}
			else{
				printf("no estaba dirigido al broadcast ethernet, es UNICAST :p\n");
				//bueno aqui va el codigo para cuando estaba la trama dirigida a una mac especifica:
				//destino ethernet bien definido, pero MAC destino en ARP DISTINA!!MALFORMACION!!
				//Este curioso caso se da por ejemplo con el DDwrt. el destino en ARP debera ser 0:0:0:0:0:0
				//POR DEBUG:
				nextState=99;
				printf("LOG:antes de comparar con zero, tengo %s y %s\n",arpDstMac,zeroMac);
				if(!strcmp(arpDstMac,zeroMac)){
					printf("LOG: por strcmp, mac destino en ARP es todo 0:  %s\n",arpDstMac);
//					dstZeroMacFlag=1;
					//es altamente probable que sea una preguntita del AP que se hace el que no sabe quien es el cliente
					//para confirmar, valido ethSrcMac con arpSrcMac y luego arpSrcMac con arpSrcIp =)
					printf("LOG:Posible mensaje del AP,compruebe que ethSrcMac matchea con arpSrcIp para descartar DoS\n");
					//tratar el error o escapar si OK
					//WARNING, marcar para comprobar y almacenar.
					//Escapa del formato de arpspoofing estudiado, me limito a mostrar el WARN, se descarta la trama
//					type="WARN";
					nextState=0;
					dropFlag=1;//descarto los del AP
				}
				//el else de abajo OJO, porque queda el resto en el que las 4 mac son iguales!!
				else{//se trata de MACs destinos AMBIGUOS, es una trama anomala!! a no ser que sea del proxyARP
					printf("LOG:por strcmp, Trama con destino definido, revisando en profundidad....Posible ProxyARP\n\n");
					//No es el caso analizado, se descarta la trama pero se indica el WARN
//					type="WARN";
					nextState=0;
					srcMacEquals=2;//por ser un caso anomalo de diferencia..
				}
			}
		}
		else{
			printf("LOG: mac destino IGUALES por strcmp, sera el caso de un mensaje respuesta ARP??\n");
			//aqui el codigo para cuando las mac destino son IGUALES:
			//macs destino coinciden, o sea bien dirigido
			//puede ser una trampa, si el origen tiene spoofeada la IP es la trama del atacante
			//o bien son tramas ARP que cayeron en el filtro (y vienen del portstealing) pero spoofeadas tambien por que no?
			//primero que nada chekeo si las MAC origen son iguales (primer verificacion, leo el resultado directamente)
			//si son iguales, veo el match MAC-IP del origen para ver si es ataque (consulto info real)

			//para el caso de la consulta ARP con destino ff:ff:ff:ff:ff:ff igual al broadcast eth, se implementa el siguiente parche
			//se evalua con el codigo de operacion y se determina si es pregunta o respuesta ARP.
			//Esto se usa a modo de parche, pero la idea es migrar todas las evaluaciones a este modo (apropiado y simple)

			if(arpPtr->arp_op/256==ARPOP_REQUEST){
				printf("LOG:puede que sea una pregunta ARP legitima proveniente de arping [detectado mediante PARCHE]\n");
                                //bien, esta trama esta marcada para verificarse integridad IP, luego steal en busqueda de spoofers
 				doCheckIpI=1;
                        	doCheckSpoofer=1;
                                nextState=1;
                                askFlag=1;//porque supongo es pregunta ARP (se usa en el programa como flag)
	                        type=0;//campo que indica que se trata de una pregunta (se usa en la trama no en el programa como flag)
        	                printf("Finalizada la evaluacion [PARCHE], continua con la carga de datos...\n");
			}
			else{
				switch(srcMacEquals){//lo puse en switch porque podria ser casos especiales de MAC Reservadas, 
							//de momento funciona igual q con IF-else
					case 1:
							//trama OK, debera verificar capa de red IP
							//si no matchea, entonces ALERTO EL ATAQUE!!!
							//SI MATCHEA, tenemos origen OK, destino OK.... nada raro.. me robe un ARP..
							printf("LOG:[Taxonomia de respuesta o ATAQUE], par[%s]-[%s]\n",ethDstMac,arpDstMac);
							//marcar para portstelear y GUARDAR el dialogo en la tabla
							doCheckIpI=1;//siempre primero, es la trivial.si conozco la info real, no noecesito el stealer.
							type=1;//Campo que indica en la trama si se trata de una respuesta arp
							nextState=1;
							arpType=1;//ES UNA RESPUESTA (podria consultar el tipo de arp desde el header...)
							//Normalmente a no ser que sea una respuesta dirigida al sabueso, no veria estas tramas...(si..con el portstl)
							//es por ello que lo mas seguro es que esta trama sean robadas del porstealing
					break;
					case 0:
							//no son iguales las MAC origen
							//Puede ser proxyARP????(ojo que esta filtrado) o bien 
								//el origen (sender) esta haciendo algo raro
							//WARNING-> inconsistencia en las MAC origen
							printf("LOG:macs origen no coinciden, posible proxyARP o trama anomala\n");
	//						type="WARN";
							nextState=2;
					break;
					default:
						printf("LOG:caso anomalo no tratado, no pudo determinarse igualdad de mac origen\n");
						nextState=98;//DEBUG
						//en estos casos, podria meter en la primer evaluacion respecto a las srcMac, numero superiores
						//para casos especiales, de momento no se trata este tipo de "mac reservada"
					break;
				}//case
			}//else del parche oparp
		}//else en el que son IGUALES las mac destino (viene del if de si son distintas)
		//antes de hacer el intento de almacenarlo en la tabla, me fijo si fue marcado para dropearlo!! (optimizacion)
		if(dropFlag==1){//drop trama
			printf("LOG: se descarta la trama efectivamente...\n");
			return;
		}
		printf("COMO NO SE DESCARTO LA TRAMA, SIGO EL PROCEDIMIENTO PARA REVISAR Y LUEGO GUARDARLA EN LA TABLA...\n");

		//PRIMERO REVISO SI ES UNA RESPUESTA ARP CONSISTENTE (SI NO ESTA SPOOFEADA), SI ES PREGUNTA, ME SALTO EL CHECK DE SPOOFERS.
			//OJO, LAS PREGUNTAS ARP PUEDEN ESTAR SPOOFEADAS Y CAUSAR ARP POISONING, PERO NO ESTA DENTRO DEL ALCANCE DE ESTE TRABAJO. (SF)
		printf("revisando si es respuesta y tiene el flag de checkipip\n");//LO DEL FLAG CHEKIPIP.. LO VOY A OBVIAR..



//acondicionando:
                        ipSrc=arpSrcIp;
                        ipDst=arpDstIp;




		//SI ES RESPUESTA:
		destinationSpoofed=0;//antes la dejo en 0 para evaluar (default NO spoofeado)
		if(arpType==1){
			printf("Se detecto que es respuesta...procediendo con rutina de check correspondiente\n");
			

			//BUSCAR EN LA TABLA DE SERVERS LA IP Y SI LA ENCUENTRO COMPROBAR LA COINCIDENCIA DE LAS MAC PARA HACER CHECK DE CONSISTENCIA

			printf("CHEKEANDO TRAFICO ARP CONTRA SPOOFERS... me ha quedado: IP_SRC= %s | IP_DST= %s \n",ipSrc,ipDst);

			printf("buscando IP extraida en la tabla de servers...\n");
			int server2guardFound=0;//no encontrado por default
			for(i=0;i<args[0].servers2guardTable_tableSize;i++){
				//COMPARAR EL LARGO PRIMERO
				printf("comparando: Leida: %s Capturada: %s \n",args[0].servers2guard_shmPtr[i].ip,ipSrc);
				if(strlen(args[0].servers2guard_shmPtr[i].ip)!=strlen(ipSrc)){
					printf("la ip tiene distinto largo\n");
					continue;//salto a la proxima entrada de la tabla
				}//si no coincide el largo
				else{//mismo largo...
					printf("tienen el mismo largo...paso a compararlas completamente...\n");
					if(!strncmp(args[0].servers2guard_shmPtr[i].ip,ipSrc,strlen(ipSrc))){
						printf("Hay coincidencias en IP leida=%s y extraida=%s en %d\n",args[0].servers2guard_shmPtr[i].ip,ipSrc,i);
						server2guardFound=1;//se encontro un server coincidente con el sender!!
						break;//rompo el lazo y continua adelante del lazo (me quedo i con el subindex del server;)
					}
					else{//Distintos
						printf("tenia el mismo largo pero la ip extraida no era la misma que el server leido en %d \n",i);
					}
				}//cierro else que entra si tienen el mismo largo

			}//continua aqui por el break
			printf("fuera del for, evaluo si se encontro o no el server\n");
			if(server2guardFound==0){//no se encontro el server y se termino el lazo
				printf("host origen %s no coincidio con ningun server monitoreado\n",ipSrc);
				printf("al no coincidir con ningun, no se realiza el check de spoofer...\n");
				//return;//DE NINGUNA MANERA... SINO NO ALMACENARIA NUNCA LAS PREGUNTAS ARP!!!!
				//continua el algoritmo para comprobar redundancias y guardar
			}
			else{//es decir, si coincidio con un server2guard o mac2guard(old version) procedo a checkear spoof antes de guardar
				//SINO..CONTINUA AQUI :=)
				printf("El host origen %s coincidio con el server monitoreado %s\n",args[0].servers2guard_shmPtr[i].ip,ipSrc);
				//comparo las MAC address:
				printf("comparando MAC capturada= %s contra MAC del server2guard= %s\n",ethSrcMac,args[0].servers2guard_shmPtr[i].mac);



				if(strlen(ethSrcMac)!=strlen(args[0].servers2guard_shmPtr[i].mac)){
					printf("SPD: SPOOFER DETECTADO!! LAS MAC NO COINCIDEN EN LARGO...\n");
//					syslog(1,"%s",spooferDetectedMessageARP);

					char *syslogAlert = NULL;
		                        syslogAlert="SPOOFER DETECTADO! ARP MSG:";
                		        syslog(1,"%s SRC: %s (%s) %s -> DST: %s %s", syslogAlert,ethSrcMac,args[0].servers2guard_shmPtr[i].mac,ipSrc,ethDstMac,ipDst);



					//return;//EN LUGAR DE HACER RETURN AQUI, MODIFICO EL VALOR DEL ASKER MAS ABAJO Y LUEGO HAGO RETURN
					destinationSpoofed=1;//like askerSpoofed
				}
				else{//sino, si tienen el mismo largo las comparo caracter a caracter
					if(!strncmp(ethSrcMac,args[0].servers2guard_shmPtr[i].mac,strlen(args[0].servers2guard_shmPtr[i].mac))){
						printf("TRANQUILO, LAS MACS SON IGUALES, LA TRAMA ES CONFIABLE...\n");
						printf("Se descarta la entrada de RESPUESTA ARP por ser el ORIGEN un SERVER2GUARD %s\n",ipSrc);
						return;
						//return;//SI DEJO RETURN,LA TRAMA NO SE ALMACENARA NUNCA! AUNQUE SEA CONFIABLE!!aunque respuestas...para que?
					}
					else{//no coinciden
						printf("SPD: SPOOFER DETECTADO POR SER DISTINTAS LAS MACS A PESAR DE TENER EL MISMO LARGO!!!!!!\n");
//						syslog(1,"%s",spooferDetectedMessageARP);
						char *syslogAlert = NULL;
	                                        syslogAlert="SPOOFER DETECTADO! ARP MSG:";
        	                                syslog(1,"%s SRC: %s (%s) %s -> DST: %s %s", syslogAlert,ethSrcMac,args[0].servers2guard_shmPtr[i].mac,ipSrc,ethDstMac,ipDst);



						//return;//EN LUGAR DE HACER RETURN AQUI, MODIFICO EL VALOR DEL ASKER MAS ABAJO Y LUEGO HAGO RETURN
						destinationSpoofed=1;//like askerSpoofed
					}
				}//ELSE
			}//Cierra el else al que entra si coincidio con un server2guard
		}//cierro el if de si es respuesta

		//EN CASOS DE DETECCION SE MODIFICARA EL INDICADOR DE STATUS AL ASKER
		// Y LUEGO SE INTERRUMPE LA EJECUCION JUSTO ANTES DE LA RUTINA DE CHECK SERVER2GUARD Y REDUNDANCIA & SAVE!
		//PERO SI NO ENTRA AL IF SIGUIENTE, ES PORQUE NO HUBO DETECCION Y SE CONTINUA CON EL PROCEDIMIENTO DE ALMACENAMIENTO.

//----------------------

                if(destinationSpoofed==1){
                        //BUSCAR AL ASKER:(RECORRER TABLA DE ASKERS)
                        for(u=0;u<ARPASKERS_TABLE_SIZE;u++){
                                printf("buscando %s en la tabla de askers\n",ipDst);//busco la IP origen en la tabla de askers

                                //chequear si coincide
                                //1| si la entrada esta en NULL entonces esta vacia, saltar a la siguiente
                                if(args[0].arpAskers_shmPtr[u].status==99){//status 99 es inicializado asi que es el "null" en este caso..
                                        printf("entrada vacia, saltar a la proxima porque estoy comparando nada mas...\n");
                                        continue;//continue salta al proximo ciclo.. break rompe el lazo y return la instancia..
                                }
                                else{//si entra aca hay algo en la entrada..compararlo entonces con la arpSrcIp que tengo
                                        printf("comparando: %s contra %s por no estar vacia la entrada\n", args[0].arpAskers_shmPtr[u].ip,ipDst);
                                        //OJO que tengo que ver que tengan el mismo strlen para asegurarme de que puedo hacer la comparacion strncmp
                                        //sino, por ejemplo si comparo 1.1.1.111 con 1.1.1.1 con strlen(1.1.1.1) me van a dar iguales!!!
                                        if(strlen(ipDst)!=strlen(args[0].arpAskers_shmPtr[u].ip)){
                                                printf("tienen diferente largo.. asi que son diferentes.. no comparo nada sin distitnas y punto\n");
                                                continue;//saltar a la proxima entrada de asker.. proximo ciclo de ESTE for
                                        }
                                        //Else continua ejecutando aqui porque no hizo el continue del IF =^.^=
                                        printf("tienen el mismo largo, pueden ser iguales, asi que las comparo...\n");
                                        //como se que si sigo aqui es porque tienen el MISMO largo, entonces comparo por strNcmp...
                                        if(!strncmp(args[0].arpAskers_shmPtr[u].ip,ipDst,strlen(ipDst))){
                                                //SI SON IGUALES, ES PORQUE TENGO AL ASKER, LO MARCO!!
                                                printf("SI: %s == %s => Lo marco para que no lo portsteleen mas\n",ipDst,args[0].arpAskers_shmPtr[u].ip);
                                                //MARCAR EL ASKER (como spoofeado, luego al romperse el while en el sabueso(fork 2) volerlo a check
                                                        //Eso de volverlo a check es porque si otro hijo estaba esperando que se unlockeara para
                                                        //chekearlo, debera poder entrar al su while sino nunca va a entrar y nadie mas podria checkearlo
printf("no se marco... por pruebas\n");
//                                              args[0].arpAskers_shmPtr[u].status=1;//spoofed (si, lo hace sin semaforo... asi de tenaz no mas!!       
                                                //HACER EL RETURN QUE LE COMENTE DEBAJO DE SYSLOG A LOS IF'S ANTERIORES
                                                return;

                                        }
                                        else{
                                                printf("al final eran diferentes, asi que paso a la siguiente a ver si encuentro el asker y lo marco\n");
                                        }
                                }//else porque status!=99
                        }//for u=0 para askers
                }//if destinationSpoofed == 1



//----------------------

		//CONTINUA LA EJECUCION PORQUE NO SE DETECTO SPOOFING...
		//PERO POR LAS DUDAS PONGO EL CORTE:
		if(destinationSpoofed==1){
			printf("ERROR: este mensaje no deberia haberse mostrado ya que el return deberia haber saltado antes!!\n");
			return;
		}
		//SI NO SE DETECTO.. CONTINUA DE LARGO (Y ESTA PERFECTO)

		//SI NO HAY ANOMALIAS CONTINUARA LA EJECUCION NORMALMENTE SI Y SOLO SI EL IPSRC NO ES UN SERVER2GUARD =)
		printf("SI he llegado aqui es porque o bien era respuesta y no estaba spofeada, o bien es una pregunta y salteo la parte del spoof check\n");
		printf("PROCEDIENDO A HACER REVISION DE REDUNDANCIA Y ALMACENAR O DESCARTAR LA TRAMA(por repeticion o por ser s2g\n");

		//ANTES QUE NADA, CORROBORO QUE EL SRC NO SEA UN SERVER2GUARD, YA QUE NO VOY A MONITOREAR POR PORTSTEALING A LOS SERVERS SINO A LOS CLIENTES
		//OJO QUE ESTO LO ACABA DE HACER ANTES.. POR AHI CON SOLO EVALUAR EL FLAG DE server2guardFound seria suficiente:

		for(i=0;i<args[0].servers2guardTable_tableSize;i++){
                        //COMPARAR EL LARGO PRIMERO
                        printf("comparando si lo que estoy por guardar es un server: Leida: %s Capturada: %s \n",args[0].servers2guard_shmPtr[i].ip,ipSrc);
                        if(strlen(args[0].servers2guard_shmPtr[i].ip)!=strlen(ipSrc)){
                                printf("la ip tiene distinto largo\n");
                                continue;//salto a la proxima entrada de la tabla
                        }//si no coincide el largo
			else{//es decir, SI "SI tienen el mismo largo", evaluo si son iguales...
				printf("como tienen el mismo largo, me fijo si son iguales...\n");
				if(!strcmp(args[0].servers2guard_shmPtr[i].ip,ipSrc)){//SI SON IGUALES
					printf("Como son iguales %s y %s, se descarta por ser server2guard\n",args[0].servers2guard_shmPtr[i].ip,ipSrc);
					return;
				}
				else{
					printf("por mas que tenian el mismo largo, no era la misma.. asi que sigo evaluando si es o no un server2guard\n");
					continue;
				}
			}
		}
		//SI SIGUE ACA.. ES PORQUE NO ERA UN SERVER2GUARD		
		printf("COMO PASO LA PRUEBA DE SI ES UN SERVER2GUARD, CONTINUO EVALUANDO SI ES UNA RESPUESTA ARP (PARA SALTARLA)\n");

		//ESTO ES NUEVO, ME INTERESAN SOLO LAS PREGUNTAS ARP YA QUE ME INTERESA CON QUIEN QUIEREN LOS CLIENTES HABLAR, ASI QUE NO VOY A GUARDAR
		//LAS RESPUESTAS XD
		
		if(arpType==1){//SI SE TRATA DE UNA RESPUESTA (OJO QUE NO MARCO EN 0 CUANDO ES PREGUNTA...)
			printf("OMITO ALMACENAMIENTO DE TRAMA POR TRATARSE DE UNA RESPUESTA, SOLO GUARDO PREGUNTAS\n");
			return;
		}
		printf("Como no se detecto que fuera respuesta, y como no es el origen un server2guard, procedo a almacenar la preguntaARP\n");

		//ENTONCES, SOLO SI NO ES RESPUESTA ARP (PERO SI ES PROTO ARP) Y SI EL SRC (EL QUE PREGUNTA) NO ES UN SERVER2GUARD, PROCEDO CON EL MECANISMO
		//DE ALMACENAMIENTO (CHECKEAR REDUNDANCIA Y GUARDAR)

		//LO HE HECHO DE ESTE MODO, PARA QUE SEA POSIBLE REVERTIR EN ALGUN CASO EL PROCEDIMIENTO Y EXISTA LA POSIBILIDAD DE ALMACENAR RESPUESTAS
		//ES DECIR, HAY CODIGO MAS ABAJO QUE NO SE VA A UTILIZAR A MENOS QUE SE TRATE DE UNA RESPUESTA.. PARECE INNECESARIO PERO DEJA
		//LA POSIBILIDAD DE IMPLEMENTAR MAS FUNCIONALIDADES BASADAS EN LAS RESPUESTAS ALMACENADAS.

		//AHORA REVISO QUE NO EXISTA DE ANTES EN LA TABLA (luego la guardo si no existe.. es para no tener redundancia)
		//COMIENZA LA PARTE EN LA QUE BUSCA UN LUGAR EN LA TABLA PARA GUARDAR LOS DATOS DE LA TRAMA CAPTURADA
		//LAZO PARA CHECKEAR SI EXISTE UNA ENTRADA IGUAL O CRUZADA DE ESTE CASO
		for(i=0;i<TABLE_SIZE;i++){//ese tamaño de la tabla de memoria deberia ser un sizeof o de alguna manera conocerlo ahora hardcodeado

			printf("\nPasada de revision %d\n",i);
			//debera comparar con todas entradas en la tabla, si coinciden TENGO UN CONOCIMIENTO, si es igual DESCARTAR
			//comprobar si existe la entrada en la tabla (de cualquier sentido) (IDA O VUELTA)
			if(askFlag==1){
				//si es una pregunta, me fijo si el pregunton esta en la tabla junto a su destino
				printf("-------------------------------------------------mostrar HIT: %d\n", args[0].shmPtr[i].hit);
			}

			//PARA COMPRAR EN LA TABLA TENGO 1 de 2 CASOS, O BIEN ES PREGUNTA O BIEN ES RESPUESTA
				//SI ES PREGUNTA ES UNIVOCA
				//SI ES RESPUESTA LA INFORMACION PUEDE SER IDENTICA O ESPECAJA (CRUZADA)

			//COMO SIRVE EL MISMO METODO, SOLO QUE EN LA RESPUESTA PUEDE QUE NECESITE ADEMAS HACERLO CRUZADO, APLICO SIEMPRE
			//EL METODO COMPATIBLE CON LA PREGUNTA ARP Y SOLO EN CASO DE NO SER UNA PREGUNTA APLICO EL CRUZADO =)

			printf("hasta ahora tengo: \n %s\n %s\n %s\n %s\n %s\n %s\n",ethSrcMac,ethDstMac,arpSrcMac,arpDstMac,arpSrcIp,arpDstIp);

			printf("estoy frente a una pregunta o respuesta ARP\n");
			//estoy aquiiii no se como comparar.. ahora se me jodio el null por la inicializacion!! (no pasa nada. uso el type ;)


			if(args[0].shmPtr[i].type==99){
				printf("\nEntrada de la tabla %d VACIA\n",i);
				printf("______________________________________________________________\n");
				continue;//salto para optimizar, sigue comparando con el proximo subindice i
			}
			//SI no estaba recien inicializada, compara valores para ver si es el mismo...
			printf("se va a compararrrrrr: %s con %s\n", ethSrcMac, args[0].shmPtr[i].ethSrcMac);
			//no uso else por el continue anterior.. asi que sigo aca else if ethsrcmac==NULL....
			printf("continuo aca no mas...\n");
			printf("la entrada %d no esta vacia..\n",i);
			printf("comparar: %s con %s \n",args[0].shmPtr[i].ethSrcMac,ethSrcMac);
			//PARCHE para el strncmp
			if(strlen(args[0].shmPtr[i].ethSrcMac)==strlen(ethSrcMac)){//si tienen el mismo largo me fijo si son la misma cadena..
				comparacion=strncmp(args[0].shmPtr[i].ethSrcMac,ethSrcMac,(int) strlen(ethSrcMac));
			}
			else{//no tienen el mismo largo (ya no son iguales ni a palos)
				printf("el ethSrcMac de la tabla no tiene el mismo largo que el ethSrcMac\n");
				comparacion=1;
			}//FIN PARCHE

			printf("valor de la comparacion = %d\n",comparacion);//0 iguales else distintos
			if(comparacion==0){//SI COINCIDIERON
				printf("resulto que eran iguales el de la entrada y este\n");
				if(srcMacEquals==1){//si las mac origen coinciden en la trama actual
					printf("se de antes que las mac origen coinciden en eth y arp\n");
					//comparo la IP origen
					//parche de consultar MISMO largo para saber si son iguales antes de strNcmp
					if(strlen(args[0].shmPtr[i].arpSrcIp)!=strlen(arpSrcIp)){
							printf("no coinciden las Ip origen: %s contra %s \n",args[0].shmPtr[i].arpSrcIp,arpSrcIp);
							dropFlag=0;//no descarte la trama...
							continue;
					}
					//si tienen el mismo largo consulto si son iguales...
					if(!strncmp(args[0].shmPtr[i].arpSrcIp,arpSrcIp,(int) strlen(arpSrcIp))){
						printf("la ip origen arp coincide en la tabla y en este caso\n");
						//comparo el destino de la trama con el de la tabla;
						//parche de consultar MISMO largo para saber si son iguales antes de strNcmp
						if(strlen(args[0].shmPtr[i].arpDstMac)!=strlen(arpDstMac)){
                                                                printf("no coinciden las Mac destino: %s contra %s \n",args[0].shmPtr[i].arpDstMac,arpDstMac);
                                                                dropFlag=0;//no descarte la trama...
                                                                continue;
                                                }
						if(!strncmp(args[0].shmPtr[i].arpDstMac,arpDstMac,(int) strlen(arpDstMac))){
							printf("tenemos la misma mac destino en ARP en tabla y en este caso..\n");
							//antes de comparar las IP me fijo si de largo son iugales (problema con .1 y .11 )
							if(strlen(args[0].shmPtr[i].arpDstIp)!=strlen(arpDstIp)){
								printf("no coinciden las IP: %s contra %s \n",args[0].shmPtr[i].arpDstIp,arpDstIp);
								dropFlag=0;//no descarte la trama...
								continue;
							}
							//misma mac destino, comparo la ip destino y listo
							if(!strncmp(args[0].shmPtr[i].arpDstIp,arpDstIp,(int) strlen(arpDstIp))){
								printf("tambien tenemos la misma IP destino...\n");
								//misma IP destino, si llego aca DESCARTOOO!!!
								printf("LOG: Coincidencia en la tabla, descartar trama\n");
								dropFlag=1;//descartar trama
								//decrementar HIT de la entrada coincidente si HIT > 2
								printf("HIT antes de restar= %d\n", args[0].shmPtr[i].hit);
								sem_wait((sem_t*) & (args[0].shmPtr[i].semaforo));
								if(args[0].shmPtr[i].hit>2){
									args[0].shmPtr[i].hit=((int) (args[0].shmPtr[i].hit)) -1;
									printf("se RESTO 1 al HIT por coincidir, valor resultante: %d\n",(int) args[0].shmPtr[i].hit);
								}
								else{
									printf("No se toca el HIT por ser  HIT <= 2: %d\n",(int) args[0].shmPtr[i].hit);
								}
								//LA MARCO PARA CHECKEAR, YA QUE NO LA INSERTO QUE CHECKEE LA QUE ESTA POR PREGUNTONA
								args[0].shmPtr[i].nextState=1;//QUE LA CHECKEE EL HIJO DEL SERVER2GUARD CORRESPONDIENTE
								sem_post((sem_t*) & (args[0].shmPtr[i].semaforo));
								break;//rompo el lazo
							}
							else{
								printf("no es la misma IP destino. Inconsistencia de datos!!\n");
								//ip destino distinta, aca ya es inconsistencia.
								//marcar para ver inconsistencia??
								//de momento no descarto
								dropFlag=0;
							}
						}
						else{
							printf("el destino no es el mismo en la tabla y en este caso..\n");
							//el destino ya no es el mismo...continuo...
						}
					}//if args.arpSrcIp == arpSrcIp
					else{
						//no es la misma trama, la ip origen no coincide para el mismo host
						printf("LOG: WARN INCONS.: srcIP no coincide para el mismo ethSrcMac en la tabla\n");
						//break???log solamente?? meter para hacer un alert???
						//me parece que lo mejor es almacenar y ya..
						//que otro se encargue de tratar las inconsistencias de la tabla
						//QUE NO SEA LA MISMA TRAMA ES SUFICIENTE PARA QUE LA GUARDE!!
					}
				}//if srcMacEquals
				else{//comparo por las dudas que sea caso anomalo ya registrado
					//NO SE GUARDA EN TABLA, SIMPLEMENTE GENERO EL WARNING (PODRIA SER OTRA TABLA?)
					//IGUAL DEBERIA VENIR YA DESCARTADO DESDE LA PRIMER VERIFICACION ESTE CASO...
					printf("LOG: WARNING: caso anomalo llego a compararse en la tabla: mac origen ambigua.. \n");
				}
			}//del if comparacion == 0
			else{//este me vino de 10, porque uso el anterior siempre... pero si NO es pregunta y no llego a conclusion,
				//pruebo tambien el cruzado :)
				printf("la comparacion dio DIFERENTE el actual y la tabla..si no es pregunta, probaria el cruzado\n");
			}

			if(askFlag==1){//si es una pregunta salteo el cruzado...
				printf("como era una pregunta arp me salteo el cruzado...\n");
				continue;//salto
			}

			//CHECK CRUZADO (en caso de ser respuesta arp..)
			printf("sigo aca porque no se trataba de una pregunta..ahora evaluo cruzado...\n");
			//REVISION CRUZADA
			//EN ESTA REVISION LO QUE HAGO ES REVISAR AL REVES LAS ENTRADAS, ES DECIR, HAGO DE CUENTA QUE EL EMISOR ES EL RECEPTOR Y COMPARO
			//ESTO LO HAGO PARA EVITAR DUPLICIDAD YA QUE LO UNICO QUE ME INTERESA ES LAS DUPLAS MAC-IP NO IMPORTA SI ES EMISOR O RECEPTOR

			printf("estoy frente a una respuesta ARP CRUZADA\n");
			printf("se va a comparar: %s con %s\n", ethSrcMac, (char*)args[0].shmPtr[i].ethDstMac);//a ver si el actual emisor fue ante receptor..y asi cruzada..
//			if(args[0].shmPtr[i].ethSrcMac == NULL){ //esta era para ver si estaba vacia, ahora asumo vaciadez si esta INICIALIZADA con el type
			if(args[0].shmPtr[i].type == 99){//inicializada sin usar...(recordar cambiar el type cuando use la entrada!!!
				printf("\nEntrada cruzada de la tabla %d VACIA\n",i);
				printf("______________________________________________________________\n");
				continue;//salto para optimizar, sigue comparando con el proximo subindice i
			}
			//no uso else por el continue anterior.. asi que sigo aca else if ethsrcmac==NULL....
			printf("continuo CRUZADO aca no mas...\n");
			printf("la entrada %d no esta vacia..\n",i);
			//parche por inclusion en el if
                        if((int)strlen(args[0].shmPtr[i].arpDstMac)!=(int)strlen(ethSrcMac)){//distinto largo.. saltar..
				printf("cruzados con distinto largo en las ethMAC: %d y %d\n",(int)strlen(args[0].shmPtr[i].arpDstMac),(int)strlen(ethSrcMac));
				comparacion=1;
                        }
			else{//tenian distinto largo.. fueron distintas al fin y al cabo..
				printf("Cruzados del mismo largo.. comparando si son iguales...\n");
				comparacion=strncmp(args[0].shmPtr[i].ethDstMac,ethSrcMac,(int) strlen(ethSrcMac));//da 0 si son the same!!
			}
			printf("valor de la comparacion cruzada = %d\n",comparacion);//0 iguales else distintos
			if(comparacion==0){//SI COINCIDIERON
				printf("resulto que eran iguales pero cruzados el de la entrada y este\n");
/*puedo evitar anidamiento aqui*/	if(srcMacEquals==1){//si las mac origen coinciden en la trama actual
					printf("se de antes que las mac origen coinciden en eth y arp\n");
					//comparo la IP origen cruzada con la destino de la tabla
					//parche para comparar largo.. si tienen distinto largo breakear
					if(strlen(args[0].shmPtr[i].arpDstIp)!=strlen(arpSrcIp)){
						printf("la arpDstIp y arpSrcIp (cruzado) tienen distinto largo\n");
						dropFlag=0;
						continue;
					}
					//else...(tienen el mismo largo...) FIN PARCHE
					if(!strncmp(args[0].shmPtr[i].arpDstIp,arpSrcIp,(int) strlen(arpSrcIp))){
						printf("la ip origen arp cruzada coincide en la tabla y en este caso\n");
						//comparo el destino de la trama con el ORIGEN de la tabla porque esta cruzada
						//parche para comparar largo.. si tienen distinto largo breakear
                                        	if(strlen(args[0].shmPtr[i].arpSrcMac)!=strlen(arpDstMac)){
							printf("la arpSrcMac y arpDstMac (cruzado) tienen distinto largo\n");
							dropFlag=0;
							continue;
						}//else...(tienen el mismo largo...) FIN PARCHE
						if(!strncmp(args[0].shmPtr[i].arpSrcMac,arpDstMac,(int) strlen(arpDstMac))){
							printf("tenemos la misma mac ORIGEN en ARP en tabla y en este caso..\n");
							//misma mac ORIGEN, comparo la ip ORIGEN en tabla con el destino de este caso y listo
							if(strlen(args[0].shmPtr[i].arpSrcIp)!=strlen(arpDstIp)){
								printf("la arpSrcIp y arpDstIp (cruzado) tienen distinto largo\n");
								dropFlag=0;                                                              
								continue;                                                           					                                                }//else...(tienen el mismo largo...) FIN PARCHE
							if(!strncmp(args[0].shmPtr[i].arpSrcIp,arpDstIp,(int) strlen(arpDstIp))){
								printf("tambien tenemos la misma IP origen cruzado...\n");
								//misma IP origen en la tabla coincide con el destino de este caso.llego aca DESCARTOOO!!!
								printf("LOG: Coincidencia CRUZADA en la tabla, descartar trama\n");
								dropFlag=1;

								//decrementar HIT de la entrada coincidente si HIT > 2
                                                                sem_wait((sem_t*) & (args[0].shmPtr[i].semaforo));
                                                                if(args[0].shmPtr[i].hit>2){
                                                                        args[0].shmPtr[i].hit=((int) (args[0].shmPtr[i].hit)) -1;
                                                                }
                                                                printf("se RESTO 1 al HIT por coincidir, valor resultante: %d\n",(int) args[0].shmPtr[i].hit);
                                                                sem_post((sem_t*) & (args[0].shmPtr[i].semaforo));

								break;//rompo el lazo
							}
							else{
								printf("no es la misma IP origen en tabla y destino en este caso. Inconsistencia de datos!\n");
								//Para comprender este caso, revisar comentarios en la revision derecha (esta es la cruzada)
								dropFlag=0;
							}
						}
						else{
							printf("el ORIGEN en la tabla no coincidio con el destino de este caso cruzado..\n");
							//el ORIGEN no es el destino (cruzados) asi que continuo...
						}
					}//if args.arpDstIp == arpSrcIp
					else{
						//no es la misma trama, la ip origen no coincide para el mismo host
						printf("LOG: WARN INCONSISTENCIA CRUZADA.: DUPLAS IP MAC NO COINCIDEN PARA LA MISMA MAC EN TABLA VS ESTE CASO (ESTA TRAMA)\n");
						//PARA COMENTARIOS AL RESPECTO REVISAR SIEMPRE LA REVISION DERECHA (ANTERIOR) Y NO LA CRUZADA (ESTA)
					}
				}//if srcMacEquals. PUEDO ELIMINAR ANIDAMIENTO CON UN SIMPLE FLAG PARA CONTINUAR O SALTAR =)
				else{//comparo por las dudas que sea caso anomalo ya registrado
					printf("LOG: WARNING en algoritmo cruzado: caso anomalo llego a compararse en la tabla: mac origen ambigua.. \n");
				}
			}//del if comparacion == 0
			else{//este me vino de 10, porque uso el anterior siempre... pero si NO es pregunta y no llego a conclusion,
				//pruebo tambien el cruzado :)
				printf("la comparacion CRUZADA dio DIFERENTE entre el caso actual y la entrada de la tabla..continuo con la sgte entrada\n");
			}
		}//LAZO FOR

//ACA VA EL CODIGO ENCARGADO DE ALMACENAR LA ENTRADA

		//cancelar si el flag de drop esta arriba (es decir, si se decidio antes dropear la trama)
		if(dropFlag!=0){
			printf("LOG: se cancela el almacenamiento de la trama por flag de DROP\n");
			return;//finaliza el tratamiento de esta trama...
		}
		else{
			printf("LOG: se procede al almacenamiento de la trama....\n");
		}

		for(i=0,savedFlag=0;i<TABLE_SIZE;i++){//lazo para almacenar datos, con flag en "unsaved" por default
			printf("___________________________________________________________________________\n");
			printf("almacenador, pasada %d\n",i);

			//dentro de este for se recorre todas las entradas de la tabla,
			// si esta "usable" la bloquea, vuelve a verificar, luego almacena y libera"
			//si esta disponible (para eliminar o para usar...)
			//if( 3 <= (((int) args[0].shmPtr[i].nextState <= 4)) ){
			
			//como no me anduvo ni la doble condicion ni el or con los || hago un switch y manejo un flag
			switch(((int) args[0].shmPtr[i].nextState)){
				case 3:
					writableFlag=1;
				break;
				case 4:
					writableFlag=1;
				break;

				default:
					printf("caso default:, no se puede usar la entrada porque su netxtState no es apropiado\n");
				break;
			}
			if(writableFlag==1){

				printf("la entrada %d esta disponible para su uso\n",i);
				//podria haber comenzado con las q se de antes que estan en NULL..(optimizar)

				//INICIA ZONA CRITICA, PIDO EL SEMAFORO
				sem_wait((sem_t*) & (args[0].shmPtr[i].semaforo));
				printf("Bloqueada la entrada %d de la tabla\n", i);
				//compruebo por las dudas de que mientras esperaba el semaforo el anterior "ocupante" haya cambiado la entrada
				writableFlag=0;
				switch(((int) args[0].shmPtr[i].nextState)){
					case 3:
						writableFlag=1;
					break;
					case 4:
						writableFlag=1;
					break;
					default:
						printf("caso default, no se puede usar la entrada\n");
					break;
				}
				if(writableFlag==1){
					printf("entrada bloqueada y libre para uso!! PERSISTIENDO DATOS...\n");
					char *cadena=NULL;
					switch(i){
						case 0:
							cadena="primer";
						break;
						case 1:
							cadena="segundo";
						break;
						case 2:
							cadena="tercero";
						break;
						default:
							cadena="mayor a tres...";
						break;
					}

					printf("**************antes de la asignacion tengo arpSrcIp %s cadena %s, nextState %d \n",arpSrcIp,cadena,nextState);

					strncpy(args[0].shmPtr[i].ethSrcMac,ethSrcMac,strlen(ethSrcMac));
					strncpy(args[0].shmPtr[i].ethDstMac,ethDstMac,strlen(ethDstMac));
					strncpy(args[0].shmPtr[i].arpSrcMac,arpSrcMac,strlen(arpSrcMac));
					strncpy(args[0].shmPtr[i].arpDstMac,arpDstMac,strlen(arpDstMac));
					strncpy(args[0].shmPtr[i].arpSrcIp,arpSrcIp,strlen(arpSrcIp));
					strncpy(args[0].shmPtr[i].arpDstIp,arpDstIp,strlen(arpDstIp));
					

					args[0].shmPtr[i].nextState=nextState;//OJO son enteros
					printf("se setea el HIT = 1 por ser creacion de entrada en tabla\n");
					args[0].shmPtr[i].hit=1;//A LA FUERZA POR SER CREACION
					if(askFlag==0){
						args[0].shmPtr[i].type=1;
						printf("se seteoo type=1 y el type era %d\n",type);
						
					}

					else{//si es pregunta...la arquitectura 0.6 especifica 0 para pregunta y el flag este es 1 para pregunta..
						args[0].shmPtr[i].type=0;
						printf("se seteoo type=0 y el type era %d\n",type);
					}
					args[0].shmPtr[i].nextState=nextState;
					printf("ya paso la asignacion por strcpy\n");
					printf("AHORA DEBERIA EVALUAR doCheckWAck=%d doCheckIpI=%d doCheckSpoofer=%d\n",doCheckWAck,doCheckIpI,doCheckSpoofer);

					//Luego.. deberia comprobar si el pregunton existe en la tabla de arpAskers..
						//Si existe tomo el index de esa entrada y lo seteo en el index de esta entrada
						//Si no existe lo inserto y luego tomo el index para guardarlo en ESTA entrada en el campo arpAskerIndex


				}
				else{//en caso fallido.. INFORMAR Y LIBERAR.. LUEGO CONTINUAR
					//OJO: para cuando se llene puedo hacer que en lugar de un for sea un while y siga y siga hasta flag saved =1..
					printf("LOG: la entrada fue modificada mientras esperaba... continuar con proxima entrada..\n");
				}
				//sleep(5);
				printf("liberando semaforo...\n");
				sem_post((sem_t*) & (args[0].shmPtr[i].semaforo));
				//FINALIZA ZONA CRITICA
				savedFlag=1;//levanto el flag para entradas guardada
			}//IF writableFlag=1
			if(savedFlag==1){//evaluo el flag que me dice si se guardo la entrada en la tabla..
				printf("se almacenaron los datos en la entrada %d de la tabla\n",i);
				break;
			}
			else{
				printf("los datos no se guardaron en la entrada %d, continuar con la siguiente....\n",i);
				continue;
			}
			//el codigo aqui no hace nada debido al continue del else anterior...

		}//FOR: lazo for para almacenar los datos en las entradas
		//verifico que paso al final tras completar el for:
		if(savedFlag==0){//no se guardo en NINGUNA entrada
			printf("LOG: WARNING: la trama no pudo almacenarse en ninguna entrada de la tabla...\n");
			//Aca podria desencadenar un procedimiento en el que se solicita a un administrador de tabla
			//que haga un mantenimiento de la misma; La comunicacion podria ser por pipe.
		}
		else{
			printf("LOG: se guardo con exito la trama en la tabla EN LA ENTRADA %d\n",i);
			tableIndex=i;//GUARDO EL INDICE DE LA ENTRADA DE LA TABLA
		}
		
		//UNA VEZ TERMINA DE RECORRER... PODRIA USAR ETIQUETAS DEL SIGUIENTE MODO:
			//1| MUESTRO MENSAJE DE TABLA LLENA Y SOLICITO AL MANTENEDOR DE TABLA QUE REVISE LA TABLA O ESPERO...
			//2| VUELVO A LA ETIQUETA DEFINIDA JUSTO ANTES DEL LAZO FOR ;) ASI INTENTO DE NUEVO..
			//3| DEFINIR UN NUMERO DE REINTENTOS.. SI SE LLEGA A ESE NUMERO, ENTONCES BREAKEAR Y MOSTRAR EL ERROR
			//OJO: NO SE SI LOS OTROS FRAMES CAPTURADOS SE VERAN AFECTADOS A LA HORA DE ALMACENAR ESTOS DATOS.. :(
				//QUIZA HASTA ESTA SEA UNA TAREA PARA HILOS :(
				

	//FINALIZA LA BUSQUEDA DE LUGAR EN LA TABLA

		//AHORA CHEQUEO SI EL ASKER EXISTE EN LA TABLA DE ASKERS.. 

		
			//SI EXISTE LE AUMENTO EL HIT
			//SI NO EXISTE LO AÑADO A LA TABLA
			//solo en el caso de que haya sido una pregunta...:
			if(askFlag==0){
				printf("Como no era una pregunta, termina el callback sin guardar askers\n");
				return;
			}
			//Sino... continua para guardar el Asker...
		


int askerFounded=0;
int askerReplace=0;
int askerSaved=0;
int askerReplaceIndex=0;//subindice de la entrada donde se encontro el asker a reemplazar (evita recorrer todo de nuevo)
		
		for(i=0,savedFlag=0;i<ARPASKERS_TABLE_SIZE;i++){
			printf("buscando %s en la tabla de askers\n",arpSrcIp);

			//chequear si coincide
			//1| si la entrada esta en NULL entonces esta vacia, saltar a la siguiente
			if(args[0].arpAskers_shmPtr[i].status==99){//status 99 es inicializado asi que es el "null" en este caso..
				printf("entrada vacia, saltar a la proxima porque estoy comparando nada mas...\n");
				continue;//continue salta al proximo ciclo.. break rompe el lazo y return la instancia..
			}
			else{//si entra aca hay algo en la entrada..compararlo entonces con la arpSrcIp que tengo
				printf("comparando: %s contra %s por no estar vacia la entrada\n", args[0].arpAskers_shmPtr[i].ip,arpSrcIp);
				//OJO que tengo que ver que tengan el mismo strlen para asegurarme de que puedo hacer la comparacion strncmp
				//sino, por ejemplo si comparo 1.1.1.111 con 1.1.1.1 con strlen(1.1.1.1) me van a dar iguales!!!
				if(strlen(arpSrcIp)!=strlen(args[0].arpAskers_shmPtr[i].ip)){
					printf("tienen diferente largo.. asi que son diferentes.. no comparo nada sin distitnas y punto\n");
					continue;//saltar a la proxima entrada de asker.. proximo ciclo de ESTE for
				}
				//Else continua ejecutando aqui porque no hizo el continue del IF =^.^=
				printf("tienen el mismo largo, pueden ser iguales, asi que las comparo...\n");
				//como se que si sigo aqui es porque tienen el MISMO largo, entonces comparo por strNcmp...
				if(!strncmp(args[0].arpAskers_shmPtr[i].ip,arpSrcIp,strlen(arpSrcIp))){
					printf("la entrada ya existe en la tabla de askers...comprobar MAC\n");
					printf("compare %s con %s y me dieron IGUALES...\n",args[0].arpAskers_shmPtr[i].ip,arpSrcIp);
					printf("comparando ahora %s con %s\n",args[0].arpAskers_shmPtr[i].mac,arpSrcMac);
					if((int)strlen(args[0].arpAskers_shmPtr[i].mac)!=(int)strlen(arpSrcMac)){
						printf("mac asker con MACS de distinto largo");
						printf("Estoy frente a un caso de reemplazo de entrada de asker...\n");
						askerReplace=1;//para que lo reemplaze
						askerReplaceIndex=i;//guardo el indice donde debo pisar el asker
						break;
					}
					else{//si tienen el mismo largo comparo a ver si son la MISMA
						if(!strncmp(args[0].arpAskers_shmPtr[i].mac,arpSrcMac,strlen(arpSrcMac))){
							printf("definitivamente la entrada ya existe.. romper bucle\n");
							askerFounded=1;//lo encontre!! levanto flag
							break;
						}
						else{//si entra en este else es porque la MAC fue distinta a pesar de ser misma IP
							printf("Tenemos nuevo host reemplazando a uno viejo o bien un caso de ip duplicado en [%d]\n",i);
							//levanto flag para reemplazar al asker
							askerReplace=1;
							//ACA podria escribir directamente en el pipe hacia el PADRE para informar el WARN
							//o escribir en alguna tabla de WARNINGS
							break;//corto el lazo for porque ya encontre coincidencia!!
						}
					}//else para cuando tienen el mismo largo las MAC de askers
				}//cierre del if de comparacion de ip en tabla asker y frame actual
				else{//si cae aca es porque la entrada no estaba vacia pero tampoco coincidio con la trama actual
					printf("askerIP tienen el mismo largo pero %s no es lo mismo que %s\n",args[0].arpAskers_shmPtr[i].ip,arpSrcIp);
				}//no era la IP que busco para el asker
			}//else NO esta inicializada nada mas (como vacia seria...)
		}//Lazo for que recorre las entradas de la tabla de arpAskers
		//Si al terminar este for no se encontro la entrada en la tabla, entonces la almaceno!!!
		if(askerFounded!=0){
			printf("El asker estaba en la tabla, asi que no lo guardo nada...\n");
			//continue;//no funciona el continue aqui dentro...
			//aumentar el HIT??
			return;
		}
		//la idea es que no se ejecute el codigo de abajo si NO hay que guardar al asker...por eso el return anterior
		else{
			printf("no se encontro al asker, asi que tengo que guardarlo\n");
		}
		//ahora bien segun sea un reemplazo o bien un ADD de asker, sigo procedimientos diferentes
		if(askerReplace==0){//solo ADD
			printf("Añadiendo asker... (no es reemplazo, solo ad)\n");
		
			//Recorrer buscando uno VACIO o iniciar algoritmo de insercion cuando la tabla esta llena (vacio ES inicializado, status:99)
			askerSaved=0;//flag que luego si pasa a 1 indicara que se almaceno la entrada en la tabla
			for(i=0,savedFlag=0;i<ARPASKERS_TABLE_SIZE;i++){
				printf("buscando una entrada vacia para guardar %s en la tabla de askers\n",arpSrcIp);
//				if(args[0].arpAskers_shmPtr[i].ip==NULL){
				if(args[0].arpAskers_shmPtr[i].status==99){//inicializada (es la adaptacion de char*=NULL a char[]=99)
					printf("entrada %d esta vacia, guardando asker...\n",i);
					//Guardar...
					sem_wait((sem_t*) & (args[0].arpAskers_shmPtr[i].semaforo));
			
					strncpy(args[0].arpAskers_shmPtr[i].ip,arpSrcIp,strlen(arpSrcIp));
					strncpy(args[0].arpAskers_shmPtr[i].mac,arpSrcMac,strlen(arpSrcMac));
					args[0].arpAskers_shmPtr[i].status=1;//este status indica q se guardo un asker;lo diferencia del inicializado (99)

					sem_post((sem_t*) & (args[0].arpAskers_shmPtr[i].semaforo));

					printf("LOG: almacenado de la entrada de asker completada...\n");
					//podria compararlo si se almaceno leyendo la entrada y strncmp con arpSrcip...
					askerSaved=1;//levanto flag de asker almacenado
					break;//porque si ya lo guarde ya esta.. no quiero continuar en el lazo for
				}
			}//lazo for que ALMACENA el asker si hay entradas vacias
		}//si era solo un ADD
		else{//significa que tengo que reemplazar una entrada...puede ser por estar llena la tabla o por conflicto de IP por eso el WARN
			printf("reemplazando asker...\n");

			askerSaved=0;
			printf("entrada %d contiene al asker que quiero reemplazar...\n",askerReplaceIndex);
			//PERFECTO ACTUALIZO LA TABLA.. PERO OJO PORQUE DEBERIA TAMBIEN QUITAR LAS ENTRADAS EN LA TABLA DE DIALOGOS!!
			sem_wait((sem_t*) & (args[0].arpAskers_shmPtr[askerReplaceIndex].semaforo));

			memset(args[0].arpAskers_shmPtr[askerReplaceIndex].ip,0,40);//limpio
			memset(args[0].arpAskers_shmPtr[askerReplaceIndex].mac,0,40);//limpio
			strncpy(args[0].arpAskers_shmPtr[askerReplaceIndex].ip,arpSrcIp,strlen(arpSrcIp));
			strncpy(args[0].arpAskers_shmPtr[askerReplaceIndex].mac,arpSrcMac,strlen(arpSrcMac));
			args[0].arpAskers_shmPtr[askerReplaceIndex].status=2;//status 2 es porque fue un replace (en general mientras mas grande mas replace?)
			//para que el comentario anterior fuera posible deberia hacer status++ peeero siempre evaluando que no alcance al 99
			//ya que el 99 es el valor de inicializacion que utilizo para estos campos de referencia.
			sem_post((sem_t*) & (args[0].arpAskers_shmPtr[askerReplaceIndex].semaforo));

			printf("PISADO de la entrada %d de asker table completada...\n",askerReplaceIndex);
			askerSaved=1;//levanto flag de asker almacenado
		}//cierro el else de if(askerReplace==0)

		if(askerSaved==0){
			printf("no se pudo almacenar al asker.. quiza la tabla este llena\n");
			printf("en realidad esta situacion no deberia ocurrir por principio... si estamos aca no funciono el algoritmo de actualizacion\n");


			//IMPORTANTE: PARA QUE NO SE LLENE LA TABLA DE DIALOGOS

			//Sucede que cuando la tabla esta llena es porque TODAS las ip del rango estan almacenadas.
			//Lo que va a pasar seguro es que si cambio un host por uno nuevo, va a cambiar la MAC pero la ip sera la del viejo host
			//En este caso, lo que tengo que hacer es evaluar cuando encuentro al asker en la tabla -> si la MAC coincide para saber
			//Si se trara o no del MISMO host. caso de ser distintos siempre almaceno el ultimo y genero una alerta en el LOG.
			//El sentido de la alerta es que podria tratarse de IP duplicada o bien de un cambio de host pero debe informarse porque
			//Ha sido descartada la entrada anterior por la nueva!!
		}
		else{
			printf("Se ingreso al asker en la tabla\n");
			
		}
		//FIN MANEJO DE ASKER TABLE
		
		//AHORA SE MARCA LA ENTRADA DE LA TABLA PARA QUE INDIQUE QUE SU ASKER HA SIDO ASOCIADO/CHEKEADO
		args[0].shmPtr[i].askerAssoc=tableIndex;//SIN SEMAFORO... LO HACE DE TENAZ NO MAS!!

		//puedo continuar con el proximo frame =) finaliza la tarea de la Callback
		//aumenta el contador de frames
		
	
	}//ELSE VIAJA ARP
fflush(stdout);
}//definicion de la funcion

