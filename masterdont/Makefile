LDNSDIR=..
CC=gcc
CFLAGS=-g3 -W -Wall -Wextra -pedantic -I$(LDNSDIR)
CFLAGS+=-D_POSIX_C_SOURCE=200112 -D_XOPEN_SOURCE=600 -D__EXTENSIONS__
LFLAGS=-L$(LDNSDIR)/lib -lcrypto
LIBS=-lldns
STATIC=$(LDNSDIR)/lib/libldns.a -lcrypto

OBJ=main.o zones.o zinfo.o server.o process.o config_file.o

all:	masterdont

all-static: $(OBJ)
	$(CC) -o masterdont $(CFLAGS) $(OBJ) $(STATIC)

masterdont: $(OBJ)
	$(CC) -o masterdont $(CFLAGS) $(OBJ) $(LFLAGS) $(LIBS)

depend:
	$(CC) $(CFLAGS) -MM *.c > makefile.dep 

clean:
	rm -f $(OBJ) masterdont

-include makefile.dep
