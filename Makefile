CC	=	gcc
CFLAGS	=	-g -Wall -Wwrite-strings -Wunused-value -Wunused-parameter

LIBOBJ=rdata.o util.o
HEADER=rdata.h prototype.h

COMPILE		= $(CC) $(CFLAGS)
LINK		= $(CC) $(CFLAGS) $(LDFLAGS)

%.o:	%.c $(HEADER)
	$(CC) $(CFLAGS) -c $<

main:	main.o $(LIBOBJ)
	$(LINK) -o $@ main.o $(LIBOBJ)
