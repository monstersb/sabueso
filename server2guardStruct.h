//This is a struct file that defines the format of server2guard struct that is stored into a servers2guard table
//@Silvestre E. Figueroa - FI-UM
//sabueso
//Esta es una entrada de la tabla de servers a cuidar con la que voy a revisar la informacion de las tramas para detectar spoofers.

typedef struct{
	char mac[40];
	char ip[40];
	int tos; //para indicar el tipo de servicio, por ej 1 para RDP, 2 para http, etc...
	char serverName[30];//ver especificaciones RFC o algo que sustente este limite (igual es para debug la info del hostname)

	//para configuracion de portStealer:

	int pstlRepeatLimit;
        int pstlPoolingTime;
        int pstlSleepTime;

	//para configuracion de sabueso:

	char nic[40];
	int serversQuantity;


}server2guardStruct;
