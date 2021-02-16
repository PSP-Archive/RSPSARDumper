TARGET = english
OBJS = english.o pspPSAR.o pspDecrypt.o pspDumper.o

INCDIR = ../include
CFLAGS = -O2 -G0 -Wall
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS) -c

LIBDIR = ../lib
LDFLAGS = 
LIBS = -lpsppower -lpspusb -lpspusb_driver -lpspusbbus_driver -lpspusbstor

PSP_FW_VERSION = 380

BUILD_PRX = 1

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak

