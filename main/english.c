#include <pspsdk.h>
#include <pspkernel.h>
#include <pspdebug.h>
#include <pspctrl.h>
#include <pspsuspend.h>
#include <psppower.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <libpsardumper.h>
#include <pspdecrypt.h>

#include <pspusbstor.h>
#include <pspusb.h>
#include <pspusbbus.h>
#include <psputility_sysparam.h>

PSP_MODULE_INFO("RSPsarDumper", 0, 1, 1);
PSP_MAIN_THREAD_ATTR(0);

#define printf    pspDebugScreenPrintf
#define HOSTFSDRIVER_NAME "USBHostFSDriver"
#define HOSTFSDRIVER_PID  (0x1C9)


#define blu 0xff0000
#define nero 0x000000
#define bianco 0xFFFFFF
#define verde_acqua 0xeeff00
#define verde_chiaro 0x00ff00
#define verde_scuro 0x009900
#define rosso 0x0000ff
#define blu 0xff0000
#define rosa 0x99CCFF
#define giallo 0x00ffff
#define bianco_verdino 0xccffcc
#define oro 0x009999
#define grigio 0x333333
#define nero 0x000000
#define marrone 0x003366
#define arancione 0x0099FF
#define fucsia 0xFF00FF
int uscita, ret;
char versione[64];


// big buffers for data. Some system calls require 64 byte alignment

// big enough for the full PSAR file
static u8 g_dataPSAR[20399999] __attribute__((aligned(64))); 

// big enough for the largest (multiple uses)
static u8 g_dataOut[3000000] __attribute__((aligned(0x40)));
   
// for deflate output
//u8 g_dataOut2[3000000] __attribute__((aligned(0x40)));
static u8 *g_dataOut2;   

char firm_version[] = { '3','.','8','0','3','.','9','0','3','.','9','3','3','.','9','5' };

#define FIRM_VERSIONS 4

void ErrorExit(int milisecs, char *fmt, ...)
{
	va_list list;
	char msg[256];	

	va_start(list, fmt);
	vsprintf(msg, fmt, list);
	va_end(list);
    pspDebugScreenSetTextColor(blu);     
	printf(msg);
	
	sceKernelDelayThread(milisecs*1000);
	sceKernelExitGame();
}


// File helpers

int ReadFile(char *file, int seek, void *buf, int size)
{
	SceUID fd = sceIoOpen(file, PSP_O_RDONLY, 0);
	if (fd < 0)
		return fd;

	if (seek > 0)
	{
		if (sceIoLseek(fd, seek, PSP_SEEK_SET) != seek)
		{
			sceIoClose(fd);
			return -1;
		}
	}

	int read = sceIoRead(fd, buf, size);
	
	sceIoClose(fd);
	return read;
}

int WriteFile(char *file, void *buf, int size)
{
	SceUID fd = sceIoOpen(file, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
	
	if (fd < 0)
	{
		return fd;
	}

	int written = sceIoWrite(fd, buf, size);

	sceIoClose(fd);
	return written;
}

static char com_table[0x4000];
static int comtable_size;

static char _1g_table[0x4000];
static int _1gtable_size;

static char _2g_table[0x4000];
static int _2gtable_size;

enum
{
	MODE_ENCRYPT_SIGCHECK,
	MODE_ENCRYPT,
	MODE_DECRYPT,
};

static int FindTablePath(char *table, int table_size, char *number, char *szOut)
{
	int i, j, k;

	for (i = 0; i < table_size-5; i++)
	{
		if (strncmp(number, table+i, 5) == 0)
		{
			for (j = 0, k = 0; ; j++, k++)
			{
				if (table[i+j+6] < 0x20)
				{
					szOut[k] = 0;
					break;
				}

				if (!strncmp(table+i+6, "flash", 5) &&
					j == 6)
				{
					szOut[6] = ':';
					szOut[7] = '/';
					k++;
				}
				else if (!strncmp(table+i+6, "ipl", 3) &&
					j == 3)
				{
					szOut[3] = ':';
					szOut[4] = '/';
					k++;
				}
				else
				{				
					szOut[k] = table[i+j+6];
				}
			}

			return 1;
		}
	}

	return 0;
}

static int FindReboot(u8 *input, u8 *output, int size)
{
	int i;

	for (i = 0; i < (size - 0x30); i++)
	{
		if (memcmp(input+i, "~PSP", 4) == 0)
		{
			size = *(u32 *)&input[i+0x2C];

			memcpy(output, input+i, size);
			return size;
		}
	}

	return -1;
}

static void ExtractReboot(int mode, char *loadexec, char *reboot, char *rebootname)
{
	int s = ReadFile(loadexec, 0, g_dataOut, sizeof(g_dataOut));

	if (s <= 0)
		return;
	
	pspDebugScreenSetTextColor(blu);
	printf("Extracting %s... ", rebootname);

	if (mode != MODE_DECRYPT)
	{
		if (mode == MODE_ENCRYPT_SIGCHECK)
		{
			memcpy(g_dataOut2, g_dataOut, s);
			pspSignCheck(g_dataOut2);

			if (WriteFile(loadexec, g_dataOut2, s) != s)
			{
              	pspDebugScreenSetTextColor(blu);                    
				ErrorExit(5000, "Cannot write %s.\n", loadexec);
			}
		}
			
		s = pspDecryptPRX(g_dataOut, g_dataOut2, s);
		if (s <= 0)
		{
            pspDebugScreenSetTextColor(blu);       
			ErrorExit(5000, "Cannot decrypt %s.\n", loadexec);
		}

		s = pspDecompress(g_dataOut2, g_dataOut, sizeof(g_dataOut));
		if (s <= 0)
		{
            pspDebugScreenSetTextColor(blu);       
			ErrorExit(5000, "Cannot decompress %s.\n", loadexec);
		}
	}

	s = FindReboot(g_dataOut, g_dataOut2, s);
	if (s <= 0)
	{
        pspDebugScreenSetTextColor(blu);       
		ErrorExit(5000, "Cannot find %s inside loadexec.\n", rebootname);
	}

	s = pspDecryptPRX(g_dataOut2, g_dataOut, s);
	if (s <= 0)
	{
        pspDebugScreenSetTextColor(blu);       
		ErrorExit(5000, "Cannot decrypt %s.\n", rebootname);
	}

	s = pspDecompress(g_dataOut, g_dataOut2, sizeof(g_dataOut));
	if (s <= 0)
	{
        pspDebugScreenSetTextColor(blu);       
		ErrorExit(5000, "Cannot decompress %s.\n", rebootname);
	}

	if (WriteFile(reboot, g_dataOut2, s) != s)
	{
        pspDebugScreenSetTextColor(blu);                       
		ErrorExit(5000, "Cannot write %s.\n", reboot);
	}
    pspDebugScreenSetTextColor(blu);     
	printf("done.\n");
}

static char *GetVersion(char *buf)
{
	char *p = strrchr(buf, ',');

	if (!p)
		return NULL;

	return p+1;
}

void stampa(int XL, int YL, char *stringa[256], u32 fgCOL, u32 bgCOL)
{
  pspDebugScreenSetTextColor(fgCOL);
  pspDebugScreenSetBackColor(bgCOL);
  pspDebugScreenSetXY(XL,YL); 
  printf("%s",stringa); 
}


void saluto()
{
 int i, y, i2, y2;
 pspDebugScreenSetTextColor(rosso);
 pspDebugScreenSetBackColor(bianco);                        
 pspDebugScreenClear();
 for(i=29; i<38; i++)
 {
  for(y=0; y<34; y++)
  {
   stampa(i,y,"O",rosso,rosso);
  }
 }
 for(i2=0; i2<72; i2++)
 {
  for(y2=14; y2<20; y2++)
  {
   stampa(i2,y2,"O",rosso,rosso);
  }
 }
 stampa(30,16,"BYE BYE",bianco,rosso);  
 stampa(27,17,"SEE YOU LATER!",bianco,rosso); 
}

int build_args(char *args, const char *execfile, int argc, char **argv)
{
	int loc = 0;
	int i;

	strcpy(args, execfile);
	loc += strlen(execfile) + 1;
	for(i = 0; i < argc; i++)
	{
		strcpy(&args[loc], argv[i]);
		pspDebugScreenSetTextColor(blu);     
		printf("Arg %i => %s\n", i, argv[i]);
		loc += strlen(argv[i]) + 1;
	}

	return loc;
}

int loadStartModule(const char *name, int argc, char **argv)
{
	SceUID modid;
	int status;
	char args[128];
	int len;

	modid = sceKernelLoadModule(name, 0, NULL);
	if(modid >= 0)
	{
		len = build_args(args, name, argc, argv);
		modid = sceKernelStartModule(modid, len, (void *) args, &status, NULL);
	}
	else
	{
        pspDebugScreenSetTextColor(blu);     
		printf("Error loading module %s\n", name);
	}

	return modid;
}

void unloadUsbhost() {
	sceUsbDeactivate(HOSTFSDRIVER_PID);
	sceUsbStop(HOSTFSDRIVER_NAME, 0, 0);
  	sceUsbStop(PSP_USBBUS_DRIVERNAME, 0, 0);
    stampa(0,28,"--------------------------------------------------------------------",nero,nero);
    stampa(0,29,"--------------------------------------------------------------------",nero,nero);
    stampa(0,30,"--------------------------------------------------------------------",nero,nero); 	
	stampa(0,28,"UsbHostfs mode disabled!",rosso,nero);
}

int main(void)
{
    int mode=0, s;
    int usbhcaricato = 1;
    int hostload=0;
    uscita = 0;
	u8 pbp_header[0x28];
	pspDebugScreenInit();
    pspDebugScreenSetBackColor(0x000000);
    pspDebugScreenSetTextColor(blu);
    pspDebugScreenClear();
    
    int firm = 0;
    
 	if (sceKernelDevkitVersion() < 0x02070110)
	{
        pspDebugScreenSetTextColor(blu);  
        printf("This program requires 2.71 or higher.\n");
		ErrorExit(10000, "If you are in a cfw, please reexecute psardumper on the higher kernel.\n");
	}

	SceUID mod = pspSdkLoadStartModule("lib.prx", PSP_MEMORY_PARTITION_KERNEL);
	if (mod < 0)
	{
        pspDebugScreenSetTextColor(blu);         
		ErrorExit(5000, "Error 0x%08X loading/starting lib.prx.\n", mod);
	}

	mod = pspSdkLoadStartModule("pspdecrypt.prx", PSP_MEMORY_PARTITION_KERNEL);
	if (mod < 0)
	{
        pspDebugScreenSetTextColor(blu);         
		ErrorExit(5000, "Error 0x%08X loading/starting pspdecrypt.prx.\n", mod);
	}
    
    	
    pspDebugScreenSetTextColor(rosso);
    printf("\n");
    printf("                RSPsar Dumper by Red Squirrel\n");	
    
    char nick[32];    
    sceUtilityGetSystemParamString(1, &nick, 32);
    pspDebugScreenSetTextColor(giallo);   
    printf("\n");
    printf("Welcome");
    pspDebugScreenSetTextColor(fucsia);    
    printf(" %s",nick);
    pspDebugScreenSetTextColor(giallo);    
    printf(" to RSPsar Dumper by Red Squirrel! ^^\n\n\n");
    
    pspDebugScreenSetTextColor(rosso);
    printf("Note: ");
    pspDebugScreenSetTextColor(blu);

  	ret = pspDecryptCode_Start();
	if(sceKernelDevkitVersion() >= 0x03080010)
	{
		if(ret == 2)
			printf("You HAVE NATIVE support for KL3E and 2LRZ now.");
		else if(ret == 1)
			printf("You HAVE NATIVE support for KL3E,but not 2LRZ. \nYou CAN'T decompress <=3.73 firmwares");
		else if(!ret)
			printf("You DON'T have NATIVE support for KL3E and 2LRZ.\nYou CAN'T decompress <=3.73 firmwares and \nreboot.bin in >=3.80");
		else
			printf("Unknow support...");
	}
	        
    pspDebugScreenSetTextColor(rosso);    
    printf("\n\n");
    printf("Comands:\n");
    pspDebugScreenSetTextColor(giallo);  
	printf("R TRIGGER:");
    pspDebugScreenSetTextColor(blu);	
    printf(" enable/disable USBHOSTFS mode.\n");	      
    pspDebugScreenSetTextColor(giallo);    
	printf("CROSS    :");
    pspDebugScreenSetTextColor(blu);	
    printf(" dump encrypted with sigcheck and decrypted reboot.bin.\n");
    pspDebugScreenSetTextColor(giallo);    
	printf("CIRCLE   :");
    pspDebugScreenSetTextColor(blu);	
    printf(" dump encrypted without sigcheck and decrypted reboot.bin.");
    pspDebugScreenSetTextColor(giallo);    
	printf("SQUARE   :");
    pspDebugScreenSetTextColor(blu);	
    printf(" dump and decrypt all.\n");
    pspDebugScreenSetTextColor(giallo);   

	printf("SELECT   :");
    pspDebugScreenSetTextColor(blu);	
    printf(" exit and come back to dashboard.\n\n");	
    
    pspDebugScreenSetTextColor(rosso);     

    printf("Thanks:\n");    
    pspDebugScreenSetTextColor(blu);
    printf("Thanks to PspPet for Psar Dumper.\n");    
	printf("Thanks to Dark_AleX for 2.80 Decryption.\n");
	printf("Thanks to Team Noobz for 3.00 Decryption.\n");
	printf("Thanks to Team C+D for 3.03 + 3.10 + 3.30 Decryption.\n");
	printf("Thanks to Team M33 for 3.60 + 3.71 Decryption.\n");
	printf("Thanks to HellDashX for 3.80 Decryption.\n");	
    printf("Thanks to Robert Metz for 3.80/3.90/3.93 Decryption.\n");
    printf("Thanks to PspGen for 3.95 Decryption.\n");	
    printf("Fw 3.90 compatibility by Red Squirrel.\n\n");
  	

	pspDebugScreenSetTextColor(giallo);
	printf("\n");


    stampa(0,27,"--------------------------------------------------------------------",bianco,nero);
    
	while (1)
	{
		SceCtrlData pad;

		sceCtrlReadBufferPositive(&pad, 1);
        
		if (pad.Buttons & PSP_CTRL_RTRIGGER)
		{
        if(usbhcaricato==0) 
        {
         unloadUsbhost();
         usbhcaricato=1;
        }
        else
        {     
              if(hostload==0)
              {    
                 loadStartModule("usbhostfs.prx", 0, NULL);	
                 hostload=1;
              }   
              
		int retVal = 0;
		retVal = sceUsbStart(PSP_USBBUS_DRIVERNAME, 0, 0);
		if (retVal != 0) {
            pspDebugScreenSetTextColor(blu);                        
			printf("Error loading USB BUS driver.\n");
			return 0;
		}
		retVal = sceUsbStart(HOSTFSDRIVER_NAME, 0, 0);
		if (retVal != 0) {
            pspDebugScreenSetTextColor(blu);                        
			printf("Error loading USB HOST driver.\n");
			return 0;
		}
		retVal = sceUsbActivate(HOSTFSDRIVER_PID);
		usbhcaricato=0;
        }
        
		sceKernelDelayThread(3000000);
        
        if(usbhcaricato==0)
        {
        int fd33 = sceIoOpen("host0:/usbhostfs.log", PSP_O_CREAT | PSP_O_RDWR, 0777);
			if(fd33 < 0) 
            { 
              stampa(0,28,"Unable to access to your PC!      ",rosso, nero);
              stampa(0,29,"Make you sure that",bianco,nero);
              pspDebugScreenSetTextColor(rosso);
              printf(" UsbHostfs.exe");              
              pspDebugScreenSetTextColor(bianco);              
              printf(" is running on your PC and then\nretry...");  
       		  sceKernelDelayThread(3000000);
              unloadUsbhost();
              usbhcaricato=1;                                           
            }
            else 
            {
             stampa(0,28,"--------------------------------------------------------------------",nero,nero);
             stampa(0,29,"--------------------------------------------------------------------",nero,nero);
             stampa(0,30,"--------------------------------------------------------------------",nero,nero);                          
             stampa(0,28,"USBHOSTFS connection correctly established!",rosso,nero);
            } 
			sceIoWrite(fd33, "OK", 2);
			sceIoClose(fd33);		
			sceIoRemove("host0:/usbhostfs.log");
        } 
		} 
		      
		if (pad.Buttons & PSP_CTRL_SELECT)
		{
            uscita=1;
			break;
		}
		
		if (pad.Buttons & PSP_CTRL_CROSS)
		{
			mode = MODE_ENCRYPT_SIGCHECK;
			break;
		}
		else if (pad.Buttons & PSP_CTRL_CIRCLE)
		{
			mode = MODE_ENCRYPT;
			break;
		}
		else if (pad.Buttons & PSP_CTRL_SQUARE)
		{
			mode = MODE_DECRYPT;
			break;
		}

		sceKernelDelayThread(10000);
	}

    if (uscita==1)
    {
        saluto();          
        ErrorExit(3000, " ");
    }
    
	sceKernelVolatileMemLock(0, (void *)&g_dataOut2, &s);

    pspDebugScreenClear();
    pspDebugScreenSetXY(0,1);
    pspDebugScreenSetTextColor(blu);
	printf("Loading Psar from Eboot...\n");
    printf("Please wait.\n");
    
    if(usbhcaricato==0)
    {
	   if (ReadFile("host0:/EBOOT.PBP", 0, pbp_header, sizeof(pbp_header)) != sizeof(pbp_header))
	   {
           printf("\n");                              
           printf("Unable to find Eboot.pbb in the same folder where UsbHostfs.exe is!\n\n");                             
		   ErrorExit(5000, "Program will end in 5 seconds...");
	   }
    }
    else
    {
	   if (ReadFile("ms0:/EBOOT.PBP", 0, pbp_header, sizeof(pbp_header)) != sizeof(pbp_header))
	   {
           printf("\n");                                      
           printf("Unable to find Eboot.pbb in the root of your Memory Stick.\n");
		   ErrorExit(5000, "Program will end in 5 seconds...");
	   }
    }        
    
    int cbFile;
    if(usbhcaricato==0)
    {    
	     cbFile = ReadFile("host0:/EBOOT.PBP", *(u32 *)&pbp_header[0x24], g_dataPSAR, sizeof(g_dataPSAR));
	     if (cbFile <= 0)
	     {
            pspDebugScreenSetTextColor(blu);                         
		    ErrorExit(5000, "Error Reading EBOOT.PBP.\n");
	     }
	     else if (cbFile == sizeof(g_dataPSAR))
	     {
            pspDebugScreenSetTextColor(blu);                   
	        ErrorExit(5000, "PSAR too big. Recompile with bigger buffer.\n");
         }
    }
    else
    {
	     cbFile = ReadFile("ms0:/EBOOT.PBP", *(u32 *)&pbp_header[0x24], g_dataPSAR, sizeof(g_dataPSAR));
	     if (cbFile <= 0)
	     {
            pspDebugScreenSetTextColor(blu);                         
		    ErrorExit(5000, "Error Reading EBOOT.PBP.\n");
	     }
	     else if (cbFile == sizeof(g_dataPSAR))
	     {
            pspDebugScreenSetTextColor(blu);                   
	        ErrorExit(5000, "PSAR too big. Recompile with bigger buffer.\n");
         }
    }

    if (memcmp(g_dataPSAR, "PSAR", 4) != 0)
    {
        pspDebugScreenSetTextColor(blu);                                
        ErrorExit(5000, "Not a PSAR file!\n");  		
    }
   
	if (pspPSARInit(g_dataPSAR, g_dataOut, g_dataOut2) < 0)
	{
        pspDebugScreenSetTextColor(blu);                                     
    	ErrorExit(5000, "pspPSARInit failed!\n");
	}

    printf("\n");
    printf("Well, eboot.pbp found and loaded correctly!\n");
    printf("Firmware version:");    
    pspDebugScreenSetTextColor(rosso);
    printf(" %s \n", GetVersion((char *)g_dataOut+0x10));
    pspDebugScreenSetTextColor(blu);
  	printf("Psar size:");
    pspDebugScreenSetTextColor(rosso);
    printf(" %d bytes\n\n\n", cbFile);
    sceKernelDelayThread(2000000);
    
    pspDebugScreenSetTextColor(rosso);
    printf("Creating DUMP folders...\n");          
    pspDebugScreenSetTextColor(giallo); 
    
    if(usbhcaricato==0)
    {          
    sceIoMkdir("host0:/DUMP", 0777); 
    sceIoMkdir("host0:/DUMP/F0", 0777);    
    printf("Directory 'host0:/DUMP/F0' created!\n"); 
    sceKernelDelayThread(200000);       
	sceIoMkdir("host0:/DUMP/F0/PSARDUMPER", 0777);
    printf("Directory 'host0:/DUMP/F0/PSARDUMPER' created!\n");
    sceKernelDelayThread(200000); 	
	sceIoMkdir("host0:/DUMP/F0/data", 0777);
    printf("Directory 'host0:/DUMP/F0/data' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("host0:/DUMP/F0/dic", 0777);
    printf("Directory 'host0:/DUMP/F0/dic' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("host0:/DUMP/F0/font", 0777);
    printf("Directory 'host0:/DUMP/F0/font' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("host0:/DUMP/F0/kd", 0777);
    printf("Directory 'host0:/DUMP/F0/kd' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("host0:/DUMP/F0/vsh", 0777);
    printf("Directory 'host0:/DUMP/F0/vsh' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("host0:/DUMP/F0/data/cert", 0777);
    printf("Directory 'host0:/DUMP/F0/data/cert' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("host0:/DUMP/F0/kd/resource", 0777);
    printf("Directory 'host0:/DUMP/F0/kd/resource' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("host0:/DUMP/F0/vsh/etc", 0777);
    printf("Directory 'host0:/DUMP/F0/vsh/etc' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("host0:/DUMP/F0/vsh/module", 0777);
    printf("Directory 'host0:/DUMP/F0/vsh/module' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("host0:/DUMP/F0/vsh/resource", 0777);
    printf("Directory 'host0:/DUMP/F0/vsh/resource' created!\n\n");	
    }
    else
    {
    sceIoMkdir("ms0:/DUMP", 0777); 
    sceIoMkdir("ms0:/DUMP/F0", 0777);    
    printf("Directory 'ms0:/DUMP/F0' created!\n"); 
    sceKernelDelayThread(200000);       
	sceIoMkdir("ms0:/DUMP/F0/PSARDUMPER", 0777);
    printf("Directory 'ms0:/DUMP/F0/PSARDUMPER' created!\n");
    sceKernelDelayThread(200000); 	
	sceIoMkdir("ms0:/DUMP/F0/data", 0777);
    printf("Directory 'ms0:/DUMP/F0/data' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("ms0:/DUMP/F0/dic", 0777);
    printf("Directory 'ms0:/DUMP/F0/dic' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("ms0:/DUMP/F0/font", 0777);
    printf("Directory 'ms0:/DUMP/F0/font' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("ms0:/DUMP/F0/kd", 0777);
    printf("Directory 'ms0:/DUMP/F0/kd' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("ms0:/DUMP/F0/vsh", 0777);
    printf("Directory 'ms0:/DUMP/F0/vsh' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("ms0:/DUMP/F0/data/cert", 0777);
    printf("Directory 'ms0:/DUMP/F0/data/cert' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("ms0:/DUMP/F0/kd/resource", 0777);
    printf("Directory 'ms0:/DUMP/F0/kd/resource' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("ms0:/DUMP/F0/vsh/etc", 0777);
    printf("Directory 'ms0:/DUMP/F0/vsh/etc' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("ms0:/DUMP/F0/vsh/module", 0777);
    printf("Directory 'ms0:/DUMP/F0/vsh/module' created!\n");	
    sceKernelDelayThread(200000);
	sceIoMkdir("ms0:/DUMP/F0/vsh/resource", 0777);
    printf("Directory 'ms0:/DUMP/F0/vsh/resource' created!\n\n");	
    }    
    
    sceKernelDelayThread(500000);
    pspDebugScreenSetTextColor(rosso);
    printf("Folder created with no problem!\n");  
    printf("Ok, I think it's time to go!\n\n");  
    sceKernelDelayThread(2000000);               
    pspDebugScreenSetTextColor(giallo);  
    
    int i;
	for(i = 0; i < FIRM_VERSIONS;i++)
	{
		if(memcmp(&firm_version[i*4],GetVersion((char *)g_dataOut+0x10),4) == 0)
		{
			firm = 1;
			break;
		}
	}   
    
    while (1)
	{
		char name[128];
		int cbExpanded;
		int pos;
		int signcheck;

		int res = pspPSARGetNextFile(g_dataPSAR, cbFile, g_dataOut, g_dataOut2, name, &cbExpanded, &pos, &signcheck);

		if (res < 0)
		{
            pspDebugScreenSetTextColor(blu);                     
			ErrorExit(5000, "PSAR decode error, pos=0x%08X.\n", pos);
		}
		else if (res == 0) /* no more files */
		{
			break;
		}
		
		if (!strncmp(name, "com:", 4) && comtable_size > 0)
		{
			if (!FindTablePath(com_table, comtable_size, name+4, name))
			{
                pspDebugScreenSetTextColor(blu);                                               
				ErrorExit(5000, "Error: cannot find path of %s.\n", name);
			}
		}

		else if (!strncmp(name, "01g:", 4) && _1gtable_size > 0)
		{
			if (!FindTablePath(_1g_table, _1gtable_size, name+4, name))
			{
                pspDebugScreenSetTextColor(blu);                                               
				ErrorExit(5000, "Error: cannot find path of %s.\n", name);
			}
		}

		else if (!strncmp(name, "02g:", 4) && _2gtable_size > 0)
		{
			if (!FindTablePath(_2g_table, _2gtable_size, name+4, name))
			{
                pspDebugScreenSetTextColor(blu);                                               
				ErrorExit(5000, "Error: cannot find path of %s.\n", name);
			}
		}
        printf("\n");
        printf("'%s' ", name);

		char* szFileBase = strrchr(name, '/');
		
		if (szFileBase != NULL)
			szFileBase++;  
		else
			szFileBase = "err.err";

		if (cbExpanded > 0)
		{
			char szDataPath[128];
			
			if (!strncmp(name, "flash0:/", 8))
			{
                if(usbhcaricato==0) sprintf(szDataPath, "host0:/DUMP/F0/%s", name+8);
                else sprintf(szDataPath, "ms0:/DUMP/F0/%s", name+8);
			}

			else if (!strncmp(name, "flash1:/", 8))
			{
				if(usbhcaricato==0) sprintf(szDataPath, "host0:/DUMP/F1/%s", name+8);
				else sprintf(szDataPath, "ms0:/DUMP/F1/%s", name+8);
			}

			else if (!strcmp(name, "com:00000"))
			{
				comtable_size = pspDecryptTable(g_dataOut2, g_dataOut, cbExpanded,firm);
							
				if (comtable_size <= 0)
				{
                    pspDebugScreenSetTextColor(blu);                                       
					ErrorExit(5000, "Cannot decrypt common table.\n");
				}

				if (comtable_size > sizeof(com_table))
				{
					ErrorExit(5000, "Com table buffer too small. Recompile with bigger buffer.\n");
				}

				memcpy(com_table, g_dataOut2, comtable_size);
                if(usbhcaricato==0) strcpy(szDataPath, "host0:/DUMP/F0/PSARDUMPER/common_files_table.bin");
                else strcpy(szDataPath, "ms0:/DUMP/F0/PSARDUMPER/common_files_table.bin");
			}
					
			else if (!strcmp(name, "01g:00000"))
			{
				_1gtable_size = pspDecryptTable(g_dataOut2, g_dataOut, cbExpanded,firm);
							
				if (_1gtable_size <= 0)
				{
					ErrorExit(5000, "Cannot decrypt 1g table.\n");
				}

				if (_1gtable_size > sizeof(_1g_table))
				{
					ErrorExit(5000, "1g table buffer too small. Recompile with bigger buffer.\n");
				}

				memcpy(_1g_table, g_dataOut2, _1gtable_size);
                if(usbhcaricato==0) strcpy(szDataPath, "host0:/DUMP/F0/PSARDUMPER/fat_files_table.bin");
                else strcpy(szDataPath, "ms0:/DUMP/F0/PSARDUMPER/fat_files_table.bin");
			}
					
			else if (!strcmp(name, "02g:00000"))
			{
				_2gtable_size = pspDecryptTable(g_dataOut2, g_dataOut, cbExpanded,firm);
							
				if (_2gtable_size <= 0)
				{
					ErrorExit(5000, "Cannot decrypt 2g table %08X.\n", _2gtable_size);
				}

				if (_2gtable_size > sizeof(_2g_table))
				{
					ErrorExit(5000, "2g table buffer too small. Recompile with bigger buffer.\n");
				}

				memcpy(_2g_table, g_dataOut2, _2gtable_size);						
				if(usbhcaricato==0)	strcpy(szDataPath, "host0:/DUMP/F0/PSARDUMPER/slim_files_table.bin");
				else strcpy(szDataPath, "ms0:/DUMP/F0/PSARDUMPER/slim_files_table.bin");
			}

			else
			{
                if(usbhcaricato==0)	sprintf(szDataPath, "host0:/DUMP/F0/PSARDUMPER/%s", strrchr(name, '/') + 1);
                else sprintf(szDataPath, "ms0:/DUMP/F0/PSARDUMPER/%s", strrchr(name, '/') + 1);
			}
            pspDebugScreenSetTextColor(verde_chiaro);
            printf("\n");
			printf("Expanding...OK!"); 
            pspDebugScreenSetTextColor(giallo);			

			if (signcheck && mode == MODE_ENCRYPT_SIGCHECK 
				&& (strcmp(name, "flash0:/kd/loadexec.prx") != 0)
				&& (strcmp(name, "flash0:/kd/loadexec_02g.prx") != 0))
			{
				pspSignCheck(g_dataOut2);
			}

			if ((mode != MODE_DECRYPT) || (memcmp(g_dataOut2, "~PSP", 4) != 0))
			{
				if (strstr(szDataPath, "ipl") && strstr(szDataPath, "2000"))
				{
					// IPL Pre-decryption
					cbExpanded = pspDecryptPRX(g_dataOut2, g_dataOut, cbExpanded);
					if (cbExpanded <= 0)
					{
                        pspDebugScreenSetTextColor(blu);                                        
						printf("Warning: cannot pre-decrypt 2000 IPL.\n");
					}
					else
					{
						memcpy(g_dataOut2, g_dataOut, cbExpanded);
					}							
				}
						
				if (WriteFile(szDataPath, g_dataOut2, cbExpanded) != cbExpanded)
	            {
					ErrorExit(5000, "Cannot write %s.\n", szDataPath);
					break;
				}
            pspDebugScreenSetTextColor(arancione);
            printf("\n");            	                    
			printf("Saving...OK!");
            pspDebugScreenSetTextColor(giallo);				
			}

			if ((memcmp(g_dataOut2, "~PSP", 4) == 0) &&
				(mode == MODE_DECRYPT))
			{
				int cbDecrypted = pspDecryptPRX(g_dataOut2, g_dataOut, cbExpanded);

				// output goes back to main buffer
				// trashed 'g_dataOut2'
				if (cbDecrypted > 0)
				{
					u8* pbToSave = g_dataOut;
					int cbToSave = cbDecrypted;
            pspDebugScreenSetTextColor(fucsia);
                        printf("\n");
					printf("Decrypting...OK!");
            pspDebugScreenSetTextColor(giallo);					
                            
					if ((g_dataOut[0] == 0x1F && g_dataOut[1] == 0x8B) ||
						memcmp(g_dataOut, "2RLZ", 4) == 0 || memcmp(g_dataOut, "KL4E", 4) == 0) 
					{
						int cbExp = pspDecompress(g_dataOut, g_dataOut2, sizeof(g_dataOut));
						
						if (cbExp > 0)
						{
            pspDebugScreenSetTextColor(verde_chiaro); 
                        printf("\n");                                 
							printf("Expanding again...OK!");
            pspDebugScreenSetTextColor(giallo);							
							pbToSave = g_dataOut2;
							cbToSave = cbExp;
						}
						else
						{
                            pspDebugScreenSetTextColor(blu);                                 
							printf("Decompress error\n"
								   "File will be written compressed.\n");
						}
					}
        			
					if (WriteFile(szDataPath, pbToSave, cbToSave) != cbToSave)
					{
						ErrorExit(5000, "Error writing %s.\n", szDataPath);
					}
            pspDebugScreenSetTextColor(arancione); 
            printf("\n");                               
					printf("Saving...OK!");
            pspDebugScreenSetTextColor(giallo);					
				}
				else
				{
					ErrorExit(5000, "Error in decryption.\n");
				}
			}

			else if (strncmp(name, "ipl:", 4) == 0)
			{
                if(usbhcaricato==0) sprintf(szDataPath, "host0:/DUMP/F0/PSARDUMPER/part1_%s", szFileBase);
                else sprintf(szDataPath, "ms0:/DUMP/F0/PSARDUMPER/part1_%s", szFileBase);
                        
				int cb1 = pspDecryptIPL1(g_dataOut2, g_dataOut, cbExpanded);
				if (cb1 > 0 && (WriteFile(szDataPath, g_dataOut, cb1) == cb1))
				{
					int cb2 = pspLinearizeIPL2(g_dataOut, g_dataOut2, cb1);
					if(usbhcaricato==0) sprintf(szDataPath, "host0:/DUMP/F0/PSARDUMPER/part2_%s", szFileBase);
					else sprintf(szDataPath, "ms0:/DUMP/F0/PSARDUMPER/part2_%s", szFileBase);
							
					WriteFile(szDataPath, g_dataOut2, cb2);
					
					int cb3 = pspDecryptIPL3(g_dataOut2, g_dataOut, cb2);
					if(usbhcaricato==0) sprintf(szDataPath, "host0:/DUMP/F0/PSARDUMPER/part3_%s", szFileBase);
					else sprintf(szDataPath, "ms0:/DUMP/F0/PSARDUMPER/part3_%s", szFileBase);
					WriteFile(szDataPath, g_dataOut, cb3);
				}
			}
		}
		else if (cbExpanded == 0)
		{
            pspDebugScreenSetTextColor(blu);                  
			printf("empty");
		}

		printf("\n");
		scePowerTick(0);
	}

    if(usbhcaricato==0) ExtractReboot(mode, "host0:/DUMP/F0/kd/loadexec.prx", "host0:/DUMP/F0/reboot.bin", "reboot.bin");
    else ExtractReboot(mode, "ms0:/DUMP/F0/kd/loadexec.prx", "ms0:/DUMP/F0/reboot.bin", "reboot.bin");
	if(usbhcaricato==0) ExtractReboot(mode, "host0:/DUMP/F0/kd/loadexec_02g.prx", "host0:/DUMP/F0/reboot_02g.bin", "reboot_02g.bin");
	else ExtractReboot(mode, "ms0:/DUMP/F0/kd/loadexec_02g.prx", "ms0:/DUMP/F0/reboot_02g.bin", "reboot_02g.bin");

    scePowerTick(0);
    pspDebugScreenClear();
    pspDebugScreenSetXY(0,1);
    pspDebugScreenSetTextColor(rosso);
    printf("Well, we have finished ^_^\n");
    printf("Program will end in three seconds!\n\n");	
    ErrorExit(3000, "Bye bye, see you later!");
    return 0;
}

