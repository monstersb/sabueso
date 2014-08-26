#include <string.h>
#include <stdio.h>

int networkSize(char *mask){
	int arpAskersTable_tableSize=10000;//MUY GRANDE
	int i =0;
	for(i=0;i<1;i++){
		if(!strncmp(mask,"255.255.255.254",strlen("255.255.255.254"))){
			printf("en cidr es una /31\n");
			arpAskersTable_tableSize=2;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.252",strlen("255.255.255.252"))){
			printf("en cidr es una /30\n");
			arpAskersTable_tableSize=4;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.248",strlen("255.255.255.248"))){
			printf("en cidr es una /29\n");
			arpAskersTable_tableSize=8;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.240",strlen("255.255.255.240"))){
			printf("en cidr es una /28\n");
			arpAskersTable_tableSize=16;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.224",strlen("255.255.255.224"))){
			printf("en cidr es una /27\n");
			arpAskersTable_tableSize=32;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.192",strlen("255.255.255.192"))){
			printf("en cidr es una /26\n");
			arpAskersTable_tableSize=64;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.128",strlen("255.255.255.128"))){
			printf("en cidr es una /25\n");
			arpAskersTable_tableSize=128;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.0",strlen("255.255.255.0"))){
			printf("en cidr es una /24\n");
			arpAskersTable_tableSize=256;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.254.0",strlen("255.255.254.0"))){
			printf("en cidr es una /23\n");
			arpAskersTable_tableSize=512;
			break;//rompe el bucle
		}
	}
	return arpAskersTable_tableSize;

}
