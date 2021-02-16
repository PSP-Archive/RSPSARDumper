	.set noreorder

#include "pspstub.s"

	STUB_START "pspDumper",0x40090000,0x00010005
	STUB_FUNC  0x2BF6093B,pspDumper_Code
	STUB_END
