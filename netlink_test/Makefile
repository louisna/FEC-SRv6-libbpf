# @author: Louis Navarre

CFLAGS += -Wall
#CFLAGS += -Werror
CFLAGS += -std=c99
CFLAGS += -O2

all: first_netlink

first_netlink:
	gcc -o first_netlink first_netlink.c $(CFLAGS)

#add_srv6: add_srv6.c
#	gcc -o add_srv6 add_srv6.c $(CFLAGS)

clean:
	rm first_netlink