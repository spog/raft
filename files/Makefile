obj-m += raft.o
raft-y := init.o conf.o relations.o socket.o netlink.o

SRC := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules V=1

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install V=1

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) clean

