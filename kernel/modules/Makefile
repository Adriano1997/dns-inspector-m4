obj-m := m4_advanced_final.o  snf_lkm.o 

KMOD_NAME := $(basename $(obj-m))
KMOD := $(KMOD_NAME).ko
SHARED_FOLDER := shared

.PHONY: all build install clean

all: build install

build:
	make -C linux M=$(shell pwd) modules
	rm -r -f *.mod.c .*.cmd *.symvers *.o

install:

	cp -av *.ko shared

	cp -av $(KMOD) shared

clean:
	make -C linux M=$(shell pwd) clean

