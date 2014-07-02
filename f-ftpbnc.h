/* f-ftpbnc.h v1.0 Headerfile
   containing structures needed by mkconfig */
/* $Rev: 1232 $ $Date: 2004-11-09 14:30:45 +0100 (Tue, 09 Nov 2004) $ */

struct CONFIG {

     char	signature[12];

     char	configname[64];

     char	localip[64];
     int	localport;

     char	desthostname[64];
     int	destport;
     char	destbindip[256];
     int	destresolvetime;

     int	hammercount;
     int	hammertime;

     int	enctype;
};

/* no need to keep secret */
const unsigned char tea_iv[8] = 
{ 0xC2, 0x69, 0x62, 0x77, 0x14, 0x78, 0xB2, 0x98 };

