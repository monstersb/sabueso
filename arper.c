/// This is an example program from the website www.microhowto.info
// © 2012 Graham Shaw
// Copying and distribution of this software, with or without modification,
// is permitted in any medium without royalty.
// This software is offered as-is, without any warranty.

// Purpose: to construct an ARP request and write it to an Ethernet interface
// using libpcap.
//
// See: "Send an arbitrary Ethernet frame using libpcap"
// http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap.html
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

//ERRORES
#define ERR_PARAM_IP "La direccion IP no es valida. Revisar formato\n"
#define ERR_PARAM_IFLONG "El nombre de la interfaz es muy largo\n"



//int arper(char* mac2guard, char* if_name, char* target_ip_string){//OLD
//arper(src_mac,src_ipiface,dst_ip,device);//NEW
int arper(char *src_mac,char *src_ip,char *dst_ip,char *if_name){

	printf("PARAMETROS RECIBIDOS EN EL ARPER: %s %s %s %s \n",src_mac,src_ip,dst_ip,if_name);


    // Construct Ethernet header (except for source MAC address).
    // (Destination set to broadcast address, FF:FF:FF:FF:FF:FF.) -> en realidad luego la seteo a gusto :p
    //estructura para cabecera ethernet
    struct ether_header header;
	//tipo de direccion
    header.ether_type=htons(ETH_P_ARP);
	//Setear direccion MAC de DESTINO. Podria luego ver de enviar algunos UNICAST (conociendo la MAC destino)
    memset(header.ether_dhost,0xff,sizeof(header.ether_dhost));

    //SETEO mac origen (0xff para broadcast). -> NOP, comentado porque yo quiero poner la MAC origen
//	memset(header.ether_shost,0xff,sizeof(header.ether_shost));

    // Construct ARP request (except for MAC and IP addresses).
    struct ether_arp req;
    req.arp_hrd=htons(ARPHRD_ETHER);
    req.arp_pro=htons(ETH_P_IP);
    req.arp_hln=ETHER_ADDR_LEN;
    req.arp_pln=sizeof(in_addr_t);
    req.arp_op=htons(ARPOP_REQUEST);
    memset(&req.arp_tha,0,sizeof(req.arp_tha));

    // Convert target IP address from string, copy into ARP request.
    struct in_addr target_ip_addr={0};
    if (!inet_aton(dst_ip,&target_ip_addr)) {
//       fprintf(stderr,"%s is not a valid IP address",dst_ip);
       write(1,ERR_PARAM_IP,sizeof(ERR_PARAM_IP));
       exit(1);
    }
    memcpy(&req.arp_tpa,&target_ip_addr.s_addr,sizeof(req.arp_tpa));


	//Aunque puede parecer tonto.. lo dejo porque no se como determina QUE placa usar todabia...la MAC se la voy a poner igual luego por argumento
    // Write the interface name to an ifreq structure,
    // for obtaining the source MAC and IP addresses. (Justo la parte de obtener la IP del sender (mi ip) me es necesaria
    struct ifreq ifr;
    size_t if_name_len=strlen(if_name);
    if (if_name_len<sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } else {
	write(1,ERR_PARAM_IFLONG,sizeof(ERR_PARAM_IFLONG));
	        //fprintf(stderr,"interface name is too long");
        exit(1);
    }
    // Open an IPv4-family socket for use when calling ioctl.
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd==-1) {
        perror(0);
        exit(1);
    }

	//SI LA IP ORIGEN ES DEFAULT, LA OBTIENE ELSE LE SETEA LA QUE VIENE

	if(0!=strncmp(src_ip, "default",strlen("default"))){
		printf("arper: se utilizara una IP spoofeada\n");
		// Convert target IP address from string, copy into ARP request.
		struct in_addr source_ip_addr={0};

		if (!inet_aton(src_ip,&source_ip_addr)) {
			//       fprintf(stderr,"%s is not a valid IP address",src_ip);
			write(1,ERR_PARAM_IP,sizeof(ERR_PARAM_IP));
			exit(1);
		}
		memcpy(&req.arp_spa,&source_ip_addr.s_addr,sizeof(req.arp_spa));//SETEAR LA IP ORIGEN CON EL ARGUMENTO CONVERTIDO EN EL IF ANTERIOR
	}
	else{//obtenerla
		printf("arper: se decidio utilizar la IP por default\n");
			

		//ESTA SERIA MI IP... LO DEJO..OJO que me parece que se vale de la NIC que recibio por argumento!!
		// Obtain the source IP address, copy into ARP request
		if (ioctl(fd,SIOCGIFADDR,&ifr)==-1) {
			perror(0);
			close(fd);
			exit(1);
		}
		//setea la IP origen con la IP de la interface seleccionada previamente
		struct sockaddr_in* source_ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
		memcpy(&req.arp_spa,&source_ip_addr->sin_addr.s_addr,sizeof(req.arp_spa));
	}//else para obtener la src_IP






	if(0==strcmp(src_mac,"default")){
		printf("arper: se utilizara la MAC del host por default");
		
		//bueno aqui debajo, obtendria la MAC de mi NIC pero como la voy a poofear lo comento
		//-------------------------------------------------------------------------------------------
    		// Obtain the source MAC address, copy into Ethernet header and ARP request.

		if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1) {
			perror(0);
			close(fd);
			exit(1);
		}
		if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
			fprintf(stderr,"not an Ethernet interface");
			close(fd);
			exit(1);
		}
		//-------------------------------------------------------------------------------------------
	
		//SETEAR LA MAC:
		//luego del if-else... ya que es el mismo codigo en ambos casos

	}//if default para src_mac
	else{//seteo la mac segun el argumento src_mac
		printf("arper: se utilizara una MAC spoofeada, porque src_mac = %s\n",src_mac);
		//convierto src_mac al formato hex
		
		char cadena[17];
		char *mac_parts[6];
		int cont=0;
		//este paso de aqui abajo, es el que me tenia mal con los otros parametros
		//por algun motivo no le gusta el char* pero si el string hardcodeado
		//esto de aqui abajo es el equivalente a poner el argumento "pegado" como si fuese ¿¿hardcodeado??

		strcpy(cadena,&src_mac[0]);//meto el char* en un array

		char *ptrToken; /* crea un apuntador char */
		ptrToken = strtok( cadena, ":" ); /* comienza la divisiÃƒÂ³n en tokens del enunciado */
		/* continua la divisiÃƒÂ³n en tokens hasta que ptrToken se hace NULL */
		cont=0;
		while ( ptrToken != NULL ) { 
		mac_parts[cont]=ptrToken;
		cont++;
		ptrToken = strtok( NULL, ":" ); /* obtiene el siguiente token */
		} 
		int mac_byte;
		unsigned char byte;
		unsigned char value;
		int i;
		//ahora un lazo for para cargar las partes de la mac en la estuctura ether
		for(i=0;i<6;i++){
		sscanf(mac_parts[i],"%x",&mac_byte);
		byte = mac_byte & 0xFF;
		value=byte;
		ifr.ifr_hwaddr.sa_data[i]=value;
		} 
	}//ELSE que setea la MAC origen determinada por el argumento src_mac cuando != default

	//UNA VEZ DECIDIDO EL VALOR DE LA MAC ORIGEN, PROCEDO A ALMACENARLA DONDE TIENE QUE IR (mismo procedimiento para default o valor especificado)
	//-------SAVEMAC
	unsigned char* source_mac_addr=(unsigned char*)ifr.ifr_hwaddr.sa_data;
	memcpy(header.ether_shost,source_mac_addr,sizeof(header.ether_shost));
	memcpy(&req.arp_sha,source_mac_addr,sizeof(req.arp_sha));
	close(fd);
	//-------END SAVEMAC


	// Combine the Ethernet header and ARP request into a contiguous block.
	unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
	memcpy(frame,&header,sizeof(struct ether_header));
	memcpy(frame+sizeof(struct ether_header),&req,sizeof(struct ether_arp));

	// Open a PCAP packet capture descriptor for the specified interface.
	printf("abriendo descriptor de capture...\n");
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0]='\0';
	pcap_t* pcap=pcap_open_live(if_name,96,0,0,pcap_errbuf);
	if (pcap_errbuf[0]!='\0') {
	fprintf(stderr,"%s\n",pcap_errbuf);
	}
	if (!pcap) {
	exit(1);
	}

	// Write the Ethernet frame to the interface.
	printf("escribiendo la trama en el cable...\n");
	//ACA LO PONGO EN UN FOR SEGUN EL ARGUMENTO QUE RECIBA, PARA SABER CUANTAS VECES INYECTAR
	//No se implemento esto, pero esta bueno porque haciendo el for aca y no desde el portStealer me evito rearmar el mensaje arp cada vez que 
		//quiero inyectar, es decir, optimizo muchisimo delegando la repeticion de tramas en este punto con un for (1 ciclo por defecto y listo)
	if (pcap_inject(pcap,frame,sizeof(frame))==-1) {
	        pcap_perror(pcap,0);
        	pcap_close(pcap);
	        exit(1);
	}
	// Close the PCAP descriptor.
	pcap_close(pcap);
	return 0;
}
