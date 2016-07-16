CC=gcc
CFLAGS= -Wall -Werror  
LDFLAGS= -lpthread

all: donmap

donmap: donmap.o donmap_worker.o 
	$(CC) $(CFLAGS) donmap.o donmap_worker.o $(LDFLAGS) -o donmap

donmap.o: donmap.c donmap.h
	$(CC) $(CFLAGS) -c donmap.c
donmap_worker.o: donmap_worker.c donmap.h 
	$(CC) $(CFLAGS) -c donmap_worker.c

clean: 
	rm *.o donmap
