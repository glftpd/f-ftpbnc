/* f-ftpbnc.h v1.1 Headerfile
   containing structures needed by mkconfig */
/* $Rev: 1558 $ $Date: 2005-07-04 20:36:13 +0200 (Mon, 04 Jul 2005) $ */

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

     int	proctitlechange;
     char	proctitletext[64];

     int	enctype;
};

/* no need to keep secret */
const unsigned char tea_iv[8] = 
{ 0xC2, 0x69, 0x62, 0x77, 0x14, 0x78, 0xB2, 0x98 };

