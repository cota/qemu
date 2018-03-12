include ../../config-host.mak
include $(SRC_PATH)/rules.mak

$(call set-vpath, $(SRC_PATH)/tests/fpu)

QEMU_INCLUDES += -I../..
# work around TARGET_* poisoning
QEMU_CFLAGS += -DHW_POISON_H

IBMFP := ibm-fptests.zip

ARCHES := aarch64
ARCHES += arm
ARCHES += ppc64
ARCHES += x86_64
OBJS := $(addprefix fpu-,$(addsuffix $(EXESUF),$(ARCHES)))

all: $(OBJS)

ibm-fptests:
	wget -nv -O $(IBMFP) http://www.haifa.il.ibm.com/projects/verification/fpgen/download/test_suite.zip
	mkdir -p $@
	unzip $(IBMFP) -d $@
	rm -rf $(IBMFP)

DEF_TARGET = $(shell echo $@ | perl -pe 's/fpu-(.*)\.o/-DTARGET_\U$$1=1/')

fpu-%.o: fpu.c
	$(CC_CMD) $(DEF_TARGET)

test: test.o

clean:
	rm -f fp *.o *.d $(OBJS)
