include ../../config-host.mak
include $(SRC_PATH)/rules.mak

$(call set-vpath, $(SRC_PATH)/tests/fpu)

QEMU_INCLUDES += -I../..

IBMFP := ibm-fptests.zip

all: fpu

ibm-fptests:
	wget -nv -O $(IBMFP) http://www.haifa.il.ibm.com/projects/verification/fpgen/download/test_suite.zip
	mkdir -p $@
	unzip $(IBMFP) -d $@
	rm -rf $(IBMFP)

fpu: fpu.o ibm-fptests

test: test.o

clean:
	rm -f fp *.o *.d
