//This is a struct file that defines the format of dialogues table.
//@Silvestre E. Figueroa - FI-UM
//sabueso

//esta estructura define el formato de las entradas de la tabla de dialogos que se guarda en la memoria compartirda.
//La memoria compartida es una estructura donde uno de los campos es un array de estas estructuras, es decir, una tabla.

struct arpDialog{
	int arpAskerIndex;//el numero de entrada en tabla arpAsker que contiene al arpSrcMac de esta entrada
	sem_t semaforo;
	char ethSrcMac[40];
	char ethDstMac[40];
	char arpSrcMac[40];
	char arpDstMac[40];
	char arpSrcIp[40];
	char arpDstIp[40];
	int type;
	int doCheckIpI;
	int doCheckSpoofer;
	int doCheckHosts;
	int nextState;
	int askerAssoc;
	int hit;
};
