PORT=54550
DEPENDENCIES = hash.h ftree.h
CFLAGS = -DPORT=$(PORT) -g -Wall -std=gnu99



all: rcopy_client rcopy_server

rcopy_server: rcopy_server.o ftree.o hash_functions.o
	
	gcc ${CFLAGS} -o $@ $^



rcopy_client: rcopy_client.o ftree.o hash_functions.o
	
	gcc ${CFLAGS} -o $@ $^
		

%.o: %.c ${DEPENDENCIES}
		
	gcc ${CFLAGS} -c $<



clean:
	rm -f *.o rcopy_client rcopy_server ftree hash_functions
