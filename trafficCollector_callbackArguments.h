//Este fichero es para poner la estructura que desde el sabueso seteo para pasar los argumentos a la funcion calback del arpCollector
//Silvestre E. Figueroa @ FI-UM 2012-2013
//Define here the arpCollector's Callback's Arguments.
#include "arpAskerStruct.h"//la incluyo en el main por transitividad de incluir este mismo archivo
#include "server2guardStruct.h"
typedef struct {
        int tableSize;
        char title[255];
        struct arpDialog* shmPtr;//puntero al array de arpDialog = seria la arpDialoguesTable
	arpAsker *arpAskers_shmPtr;//puntero al array (tabla) de arpAsker -> la tabla arpAskersTable[]
	int arpAskers_tableSize;
	server2guardStruct *servers2guard_shmPtr;//puntero al array (tabla) de server2guardStruct -> tabla servers2guardTable[]
	int servers2guardTable_tableSize;
}trafficCCArgs;//arpCollectorCallbackArguments
