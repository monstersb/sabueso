CFLAGS= -Wall -g -lrt -lpthread -lpcap -lconfig
all: sabueso
sabueso: sabueso.o trafficCollector_callback.o arper.o parser.o networkSizer.o pstFunction.o
	$(CC) -o $@ $^ $(CFLAGS)
clean:
	rm -fv *.o
	rm -fv sabueso
	rm -fv *~
	rm salee
