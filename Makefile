SRCS = nanomsg-handler.c red_black_tree.c string_tree.c parser.c stack.c misc.c

HDRS = parser.h string_tree.h

OBJS = misc.o parser.o red_black_tree.o stack.o string_tree.o

CC = g++ -Wno-write-strings

CFLAGS = -g -Wall -pedantic 

PROGRAM = ./libs/nanomsg-handler.so

.PHONY:	mem_check clean

all: $(PROGRAM)

$(PROGRAM): 	$(SRCS)
	apxs -S CC=g++ -i -a -c $(SRCS) -lnanomsg -lstdc++
		
clean:			
	rm -f *.o *.lo *.la *.slo *~ *.exp *.lib *.so *.obj






