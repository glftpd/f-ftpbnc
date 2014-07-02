/* f-ftpbnc v1.0 */
/* $Rev: 1232 $ $Date: 2004-11-09 14:30:45 +0100 (Tue, 09 Nov 2004) $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/select.h>

#include <signal.h>

#include "sha256.h"
#include "xtea-cipher.h"

#include "f-ftpbnc.h"

#define IDENTD_PORT 		113
#define TIMER_MULTIPLY		1000

#define TIMEOUT_IDENT		10 * TIMER_MULTIPLY
#define TIMEOUT_CONNECTING	20 * TIMER_MULTIPLY
#define TIMEOUT_CONNECTED	3*3600 * TIMER_MULTIPLY

/* #define DEBUG_SELECT */

/*** config loader/decrypter/decrambler ***/

/* should be only be saved encrypted in program image */

#include "inc-config.h"

const struct CONFIG *config;

int config_load() {

#if defined(SCRAMBLE_CONFIG)

     xtea_cbc_decipher(configdataencrypt, sizeof(configdataencrypt),
		       (unsigned long*)configkey, tea_iv);

     config = (struct CONFIG*)configdataencrypt;

#elif defined(ENCRYPT_CONFIG)

     char *inpass;
     unsigned char teakey[16];

     inpass = getpass("Password: ");
     if (!inpass) {
	  printf("Could not read password.\n");
	  return 0;
     }

     string_to_teakey(inpass, teakey);

     memset(inpass, 0, strlen(inpass));
         
     xtea_cbc_decipher(configdataencrypt, sizeof(configdataencrypt),
		       (unsigned long*)teakey, tea_iv);

     config = (struct CONFIG*)configdataencrypt;

#else
#error "No Configuration Available?"
#endif

     if (strncmp(config->signature, "f-ftpbnc", 9) == 0) return 1;

     printf("Configuration could not be read. Password is wrong?\n");

     return 0;
}

/*** debug output functions ***/

#define aprintf(args...)	_aprintf(__FILE__, __LINE__, args)
#define aprintferrno(args...)	_aprintferrno(__FILE__, __LINE__, args)

int aprintf_output = 0;

inline void _aprintf(const char *file, int line, const char *format, ...) {
     va_list ap;
     static char output[1024];
     
     if (!aprintf_output) return;

     va_start(ap, format);
     vsnprintf(output, sizeof(output), format, ap);
     va_end(ap);

     fprintf(stderr, "%s:%d> %s\n", file, line, output);
     
     return;
}

inline void _aprintferrno(const char *file, int line, const char *format, ...) {
     va_list ap;
     static char output[1024];

     if (!aprintf_output) return;
     
     va_start(ap, format);
     vsnprintf(output, sizeof(output), format, ap);
     va_end(ap);

     fprintf(stderr, "%s:%d> %s (errno %d : %s)\n", file, line, output, errno, strerror(errno));
     
     return;
}

/*** USR signal handler ***/

void signal_INT(int signum) {

     /* reset handler for new signals */
     signal(signum, signal_INT);

     aprintf("Received SIGINT");

     exit(0);
}

void signal_USR1(int signum) {

     /* reset handler for new signals */
     signal(signum, signal_USR1);

     aprintf("Received SIGUSR1");

     /* do nothing (esp not terminate) */
}

void signal_USR2(int signum) {

     /* reset handler for new signals */
     signal(signum, signal_USR2);

     aprintf("Received SIGUSR2");

     /* do nothing (esp not terminate) */
}

void signal_PIPE(int signum) {

     /* reset handler for new signals */
     signal(signum, signal_PIPE);

     aprintf("Received SIGPIPE");

     /* do nothing (esp not terminate) */
}

/*** Network Functions ***/

int net_newsocket() {
     struct protoent *pe;
     int tcpprotonum = 0;
     int socketnum;
     int sockoptflag;

     pe = getprotobyname("tcp");
     if (pe) {
	  tcpprotonum = pe->p_proto;
     }

     socketnum = socket(AF_INET, SOCK_STREAM, tcpprotonum);
     if (socketnum == -1) {
	  aprintferrno("Cannot allocate new socket");
	  return -1;
     }

     sockoptflag = 1;
     /* Enable sending of keep-alive messages on connection-oriented sockets. */
     if (setsockopt(socketnum, SOL_SOCKET, SO_KEEPALIVE, &sockoptflag, sizeof(sockoptflag)) != 0) {
	  aprintferrno("Cannot set SO_KEEPALIVE on socket");
     }

     /* set SO_REUSEPORT */
#ifdef SO_REUSEPORT
     if (setsockopt(socketnum, SOL_SOCKET, SO_REUSEPORT, &sockoptflag, sizeof(sockoptflag)) != 0) {
	  aprintferrno("Cannot set SO_REUSEPORT on socket");
     }
#else
     if (setsockopt(socketnum, SOL_SOCKET, SO_REUSEADDR, &sockoptflag, sizeof(sockoptflag)) != 0) {
	  aprintferrno("Cannot set SO_REUSEADDR on socket");
     }
#endif

     /* maybe IP_TOS in future */

     /* TCP_NODELAY
	If set, disable the Nagle algorithm. This means that segments are always sent as soon 
	as possible, even if there is only a small amount of data.  When not set, data is 
	buffered until there is a sufficient amount to send out, thereby  avoiding the frequent
	sending of small packets, which results in poor utilization of the network. This option
	cannot be used at the same time as the option TCP_CORK. */
#ifdef SOL_TCP
     if (setsockopt(socketnum, SOL_TCP, TCP_NODELAY, &sockoptflag, sizeof(sockoptflag)) != 0) {
#else
     if (setsockopt(socketnum, 6, TCP_NODELAY, &sockoptflag, sizeof(sockoptflag)) != 0) {
#endif
	  aprintferrno("Cannot set TCP_NODELAY on socket");
     }

     return socketnum;
}

unsigned long net_resolvehost(const char *host)
{
     struct in_addr ia;
     struct hostent *he;

     if (inet_aton(host, &ia)) {
	  return ia.s_addr;
     }
     
     he = gethostbyname(host);
     if (he == NULL) {
	  return 0;
     } else {
	  return *(unsigned long *)he->h_addr;
     }
}

int net_bindsocket(int sockfd, const char *ip, unsigned short port)
{
     struct sockaddr_in	sa;

     sa.sin_family = AF_INET;
     sa.sin_port = htons(port);

     if (ip != NULL) {
	  if (strncmp(ip,"*", 2) == 0) {
	       sa.sin_addr.s_addr = htonl(INADDR_ANY);
	  } else {
	       if (!(sa.sin_addr.s_addr = net_resolvehost(ip))) {
		    aprintferrno("Cannot resolve host");
		    return 0;
	       }
	  }
     }
     else {
	  sa.sin_addr.s_addr = htonl(INADDR_ANY);
     }

     if (bind(sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr)) != 0) {
	  aprintferrno("Cannot bind socket");
	  return 0;
     }

     return 1;
}

int net_connect(int sockfd, const char *ip, unsigned short port)
{
     struct sockaddr_in	sa;
     int r;

     sa.sin_family = AF_INET;
     sa.sin_port = htons(port);

     if (!(sa.sin_addr.s_addr = net_resolvehost(ip))) {
	  aprintferrno("Cannot resolve host");
	  return 0;
     }

     r = connect(sockfd, (struct sockaddr *) &sa, sizeof (sa));
     if (r < 0 && errno == EINPROGRESS) {
	  return 2;
     }
     if (r == 0) {
	  return 1;
     }

     return 0;
}

const char *get_destinationip_cached()
{
     static int lastresolv = 0;
     static int cfgisip = 0;
     static struct hostent *he = NULL;

     int timenow = time(NULL);
     struct in_addr ia;
     struct hostent *he_new;

     if (cfgisip) return config->desthostname;

     if (lastresolv + config->destresolvetime <= timenow) {

	  if (inet_aton(config->desthostname, &ia)) {
	       cfgisip = 1;
	       return config->desthostname;
	  }

	  aprintf("Resolving hostname %s", config->desthostname);
	  he_new = gethostbyname(config->desthostname);
	  if (he_new != NULL) {
	       he = he_new;
	  }
	  lastresolv = timenow;
     }     

     if (!he) return NULL;

     return inet_ntoa(*(struct in_addr *)he->h_addr);
}

/*** Hammer Protection Counting array ***/

struct HAMMER
{
     time_t            ltime;
     in_addr_t         lconn;
};

struct HAMMER *hammerlist = NULL;
int hammerlistlen = 0;

int hammer_check(struct sockaddr_in client)
{
     int n, freen, clientcount;
     time_t tnow = time(NULL);

     if (config->hammercount == 0) return 1;

     if (!hammerlist) {
	  /* approximate a good hammer list length */
	  hammerlistlen = config->hammercount * config->hammertime * 2;
	  hammerlist = (struct HAMMER*)malloc(sizeof(struct HAMMER) * hammerlistlen);
	  memset(hammerlist, 0, sizeof(struct HAMMER) * hammerlistlen);
	  aprintf("Hammerlist allocated with %d entries", hammerlistlen);
     }

     clientcount = 0;
     freen = -1;

     for(n = 0; n < hammerlistlen; n++) {
	  if (hammerlist[n].ltime >= (tnow - config->hammertime) && 
	      client.sin_addr.s_addr == hammerlist[n].lconn)
	  {
	       clientcount++;
	  }

	  if (hammerlist[n].ltime == 0) {
	       if (freen < 0) freen = n;
	       break;
	  }
	  if (freen < 0 && hammerlist[n].ltime < (tnow - config->hammertime)) freen = n;
     }

     aprintf("Hammerlist found %d connects within last %d secs. Free entry %d will be filled.",
	     clientcount, config->hammertime, freen);

     if (clientcount >= config->hammercount) return 0;
 
     if (freen >= 0) {
	  hammerlist[freen].ltime = tnow;
	  hammerlist[freen].lconn = client.sin_addr.s_addr;
     }

     return 1;
}

/*** Socket Status array ***/

struct SOCK;

typedef int (*socket_proc)(struct SOCK *status);

enum { STATUS_ERROR,
       STATUS_CLIENTFORWARD,
       STATUS_SERVERCONNECTING, STATUS_SERVERIDENT, STATUS_SERVERCONNECTED,
       STATUS_IDENTCONNECTING, STATUS_IDENTCONNECTED };

struct SOCK
{
     int		used;

     int		status;

     int		sockfd;
     socket_proc	readhandler;
     socket_proc	writehandler;
     socket_proc	excepthandler;
     long		timeout;

     char		linebuffer[128];
     unsigned int	linebufferlen;

     char		*ident;

     struct SOCK*	forwardsock;
     struct SOCK*	identsock;

     struct sockaddr_in	sockaddr;

     int		oldfcntlflags;
};

int socketsnum = 0;
struct SOCK **sockets;
int socketsused = 0;

struct SOCK *socklist_findunused() {
     int n, oldsocketsnum;
     for(n = 0; n < socketsnum; n++) {
	  if (sockets[n]->used) continue;

	  memset(sockets[n], 0, sizeof(struct SOCK));
	  return sockets[n];
     }
     
     /* grow sockets list */
     oldsocketsnum = socketsnum;
     socketsnum += 10;

     if (oldsocketsnum == 0) {
	  sockets = (struct SOCK**)malloc(socketsnum * sizeof(struct SOCK*));
     }
     else {
	  sockets = (struct SOCK**)realloc(sockets, socketsnum * sizeof(struct SOCK*));
     }

     for(n = oldsocketsnum; n < socketsnum; n++) {
	  sockets[n] = malloc(sizeof(struct SOCK));
	  memset(sockets[n], 0, sizeof(struct SOCK));
     }

     return sockets[oldsocketsnum];
}

/* Cleanup socket */

void socket_close(struct SOCK *ss) {

     aprintf("Closing socket fd %d", ss->sockfd);

     if (close(ss->sockfd) != 0) {
	  aprintferrno("Error closing socket");
     }

     ss->used = 0;
     socketsused--;
}

/* flush ident into and line buffer to server when its connected */

void socket_flush(struct SOCK *ss) {
     static char buff[512];
     struct SOCK *clt = ss->forwardsock;

     if (!clt) {
	  aprintf("Stray server socket. Closing.");
	  socket_close(ss);
	  return;
     }     

     if (clt->ident) {
	  snprintf(buff, sizeof(buff),
		   "IDNT %s@%s:%s\n",
		   clt->ident, inet_ntoa(clt->sockaddr.sin_addr), inet_ntoa(clt->sockaddr.sin_addr));

	  if (write(ss->sockfd, buff, strlen(buff)) != (signed)strlen(buff)) {
	       aprintferrno("Short write");
	  }
     
	  aprintf("Sending %s", buff);

	  free(clt->ident);
	  clt->ident = NULL;
     }

     if (ss->linebufferlen > 0) {	       
	  /* Write out buffered data from client */
	  if (write(ss->sockfd, ss->linebuffer, ss->linebufferlen) != (signed)ss->linebufferlen) {
	       aprintferrno("Short write");
	  }

	  aprintf("Flushed %d bytes from line buffer to socket %d", ss->linebufferlen, ss->sockfd);

	  ss->linebufferlen = 0;
     }
}

/*** Client/Server Data Relay function ***/

int main_relaydata(struct SOCK *ss) {
     int inbytes, outbytes;
     static char inbuffer[4096];

     if (ss->status == STATUS_CLIENTFORWARD) {
	  struct SOCK *fs = ss->forwardsock;
	  
	  if (!fs) {
	       aprintf("Received data on socket with not forwardsock.");
	       socket_close(ss);
	       return 0;
	  }

	  if (fs->status == STATUS_SERVERCONNECTING || fs->status == STATUS_SERVERIDENT) {
	       /* Queue data in linebuffer */

	       if (fs->linebufferlen < sizeof(fs->linebuffer) - 16) {
		    inbytes = read(ss->sockfd, fs->linebuffer + fs->linebufferlen, sizeof(fs->linebuffer) - fs->linebufferlen);

		    if (inbytes < 0) {
			 aprintferrno("Error reading from client socket fd %d", ss->sockfd);
			 socket_close(fs);
			 socket_close(ss);
			 return 0;
		    }
		    if (inbytes == 0) { 
			 aprintf("EOF received on client socket fd %d", ss->sockfd);
			 socket_close(ss);
			 return 0;
		    }
		    
		    aprintf("Buffering data from client socket at position %d -> %d bytes received", fs->linebufferlen, inbytes);
		    fs->linebufferlen += inbytes;
		    ss->timeout = TIMEOUT_CONNECTED;
	       }
	       else {
		    aprintf("Linebuffer for socket %d is full. Cannot queue more data. Ignoring read request.", ss->sockfd);
	       }
	  }
	  else if (fs->status == STATUS_SERVERCONNECTED) {
	       /* write data onto forwarded socket */

	       inbytes = read(ss->sockfd, inbuffer, sizeof inbuffer);

	       if (inbytes < 0) {
		    aprintferrno("Error reading from client socket fd %d", ss->sockfd);
		    socket_close(fs);
		    socket_close(ss);
		    return 0;
	       }
	       if (inbytes == 0) {
		    aprintf("EOF received on client socket fd %d", ss->sockfd);
		    socket_close(fs);
		    socket_close(ss);
		    return 0;
	       }

	       ss->timeout = TIMEOUT_CONNECTED;

	       outbytes = write(fs->sockfd, inbuffer, inbytes);
	       
	       if (outbytes < 0) {
		    aprintferrno("Error writing to server socket fd %d", ss->sockfd);
		    socket_close(fs);
		    socket_close(ss);
		    return 0;
	       }

	       if (outbytes != inbytes) {
		    aprintferrno("Short write.");
	       }

	       aprintf("Forwarded %d bytes from client %d to server %d", inbytes, ss->sockfd, fs->sockfd);
	  }
	  else {
	       aprintf("Error in status for forwarded socket.");
	       socket_close(fs);
	       socket_close(ss);
	  }
     }
     else if (ss->status == STATUS_SERVERCONNECTED) {
	  struct SOCK *fs = ss->forwardsock;
	  
	  if (!fs) {
	       aprintf("Received data on socket without forwardsock.");
	       socket_close(ss);
	       return 0;
	  }

	  /* write data onto forwarded socket */

	  inbytes = read(ss->sockfd, inbuffer, sizeof inbuffer);

	  if (inbytes < 0) {
	       aprintferrno("Error reading from server socket fd %d", ss->sockfd);
	       socket_close(fs);
	       socket_close(ss);
	       return 0;	       
	  }
	  if (inbytes == 0) {
	       aprintf("EOF received on server socket fd %d", ss->sockfd);
	       socket_close(fs);
	       socket_close(ss);
	       return 0;
	  }

	  ss->timeout = TIMEOUT_CONNECTED;

	  outbytes = write(fs->sockfd, inbuffer, inbytes);

	  if (outbytes < 0) {
	       aprintferrno("Error writing to socket");
	       socket_close(fs);
	       socket_close(ss);
	       return 0;
	  }

	  if (outbytes != inbytes) {
	       aprintferrno("Short write.");
	  }

	  aprintf("Forwarded %d bytes from server %d to client %d", inbytes, ss->sockfd, fs->sockfd);
     }
     else {
	  aprintf("Invalid status for socket fd %d: %d", ss->sockfd, ss->status);
     }

     return 0;
}

/* handle async connect to clients identd */

void sanitize_ident(char *i) {
     while(*i) {
	  if (*i == '@') *i = '.';
	  if (*i == '*') *i = '.';
	  if (*i == '[') *i = '.';
	  if (*i == ']') *i = '.';
	  if (*i == '{') *i = '.';
	  if (*i == '}') *i = '.';        
	  i++;
     }
}

int main_readidentd(struct SOCK *ss) {
     int inbytes, r;
     static char inbuffer[4096], ident[256];
     int remote_port, local_port;
	 
     struct SOCK *cltss = ss->forwardsock; 
     struct SOCK *srvss;

     if (!cltss) {
	  aprintf("Stray ident socket. Closing.");
	  socket_close(ss);
	  return 0;
     }

     srvss = cltss->forwardsock;
     if (!srvss) {
	  aprintf("Stray ident socket. Closing.");
	  socket_close(cltss);
	  socket_close(ss);
	  return 0;
     }

     /* read data from ident socket */

     inbytes = read(ss->sockfd, inbuffer, sizeof inbuffer);
     
     if (inbytes < 0) {
	  aprintferrno("Error reading from ident socket");
	  socket_close(ss);

	  /* save * as ident */
	  cltss->ident = strdup("*");

	  if (srvss->status == STATUS_SERVERIDENT) {
	       socket_flush(srvss);

	       srvss->status = STATUS_SERVERCONNECTED;
	       srvss->readhandler = main_relaydata;
	       srvss->timeout = TIMEOUT_CONNECTED;

	       cltss->timeout = TIMEOUT_CONNECTED;
	  }
	  return 0;
     }
     if (inbytes == 0) {
	  aprintf("EOF received on ident socket fd %d", ss->sockfd);
	  socket_close(ss);

	  /* save * as ident */
	  cltss->ident = strdup("*");

	  if (srvss->status == STATUS_SERVERIDENT) {
	       socket_flush(srvss);

	       srvss->status = STATUS_SERVERCONNECTED;
	       srvss->readhandler = main_relaydata;
	       srvss->timeout = TIMEOUT_CONNECTED;

	       cltss->timeout = TIMEOUT_CONNECTED;
	  }
	  return 0;
     }

     inbuffer[inbytes] = 0;
     r = sscanf(inbuffer, "%d , %d : USERID :%*[^:]:%255s", &remote_port, &local_port, ident);

     /* check ident responce */
     if (r != 3 || remote_port != ntohs(cltss->sockaddr.sin_port) || local_port != config->localport) {

	  r = sscanf(inbuffer, "%d , %d : ERROR :", &remote_port, &local_port);

	  if (r != 2 || remote_port != ntohs(cltss->sockaddr.sin_port) || local_port != config->localport) {
	       aprintf("Bogus ident reply: %s\n",inbuffer);
	       socket_close(ss);

	       /* save * as ident */
	       cltss->ident = strdup("*");

	       if (srvss->status == STATUS_SERVERIDENT) {
		    socket_flush(srvss);

		    srvss->status = STATUS_SERVERCONNECTED;
		    srvss->readhandler = main_relaydata;
		    srvss->timeout = TIMEOUT_CONNECTED;

		    cltss->timeout = TIMEOUT_CONNECTED;
	       }
	       return 0;
	  }
	  strcpy(ident, "*");
     }

     aprintf("Received ident %s", ident);
     socket_close(ss);

     cltss->ident = strdup(ident);
     sanitize_ident(cltss->ident);

     cltss->timeout = TIMEOUT_CONNECTED;

     if (srvss->status == STATUS_SERVERIDENT) {
	  socket_flush(srvss);
     
	  srvss->status = STATUS_SERVERCONNECTED;
	  srvss->readhandler = main_relaydata;
	  srvss->timeout = TIMEOUT_CONNECTED;
     }
     return 0;
}

int main_identdconnect(struct SOCK *ss) {
     int error, r;
     unsigned int len;
     static char buff1[256];

     struct SOCK *cltss = ss->forwardsock;
     struct SOCK *srvss;

     if (!cltss) {
	  aprintf("Stray ident socket. Closing.");
	  socket_close(ss);
	  return 0;
     }

     srvss = cltss->forwardsock;
     if (!srvss) {
	  aprintf("Stray ident socket. Closing.");
	  socket_close(cltss);
	  socket_close(ss);
	  return 0;
     }

     len = sizeof(error);
     if (getsockopt(ss->sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
	  aprintf("Could not get errno from async ident socket.");
	  socket_close(ss);

	  /* save * as ident */
	  cltss->ident = strdup("*");

	  if (srvss->status == STATUS_SERVERIDENT) {
	       socket_flush(srvss);

	       srvss->status = STATUS_SERVERCONNECTED;
	       srvss->readhandler = main_relaydata;
	       srvss->timeout = TIMEOUT_CONNECTED;

	       cltss->timeout = TIMEOUT_CONNECTED;
	  }
	  return 0;
     }

     if (error != 0) {
	  aprintf("Could not connect to ident port: %s", strerror(error));
	  socket_close(ss);

	  /* save * as ident */
	  cltss->ident = strdup("*");

	  if (srvss->status == STATUS_SERVERIDENT) {
	       socket_flush(srvss);

	       srvss->status = STATUS_SERVERCONNECTED;
	       srvss->readhandler = main_relaydata;
	       srvss->timeout = TIMEOUT_CONNECTED;

	       cltss->timeout = TIMEOUT_CONNECTED;
	  }
	  return 0;
     }

     if (fcntl(ss->sockfd, F_SETFL, ss->oldfcntlflags) != 0) {
	  aprintferrno("Cannot set ident connection socket back to blocking");
     }

     ss->writehandler = NULL;
     ss->readhandler = main_readidentd;
     aprintf("Ident Connection established. Requesting ident for %d,%d", ntohs(cltss->sockaddr.sin_port), config->localport);

     snprintf(buff1, sizeof(buff1),
	      "%d,%d\r\n", ntohs(cltss->sockaddr.sin_port), config->localport);

     r = write(ss->sockfd, buff1, strlen(buff1));
     if (r < 0) {
	  aprintferrno("Error writing to ident socket.\n");
	  socket_close(ss);

	  /* save * as ident */
	  cltss->ident = strdup("*");

	  if (srvss->status == STATUS_SERVERIDENT) {
	       socket_flush(srvss);

	       srvss->status = STATUS_SERVERCONNECTED;
	       srvss->readhandler = main_relaydata;
	       srvss->timeout = TIMEOUT_CONNECTED;

	       cltss->timeout = TIMEOUT_CONNECTED;
	  }
     }
     
     return 0;
}

int main_identdtimeout(struct SOCK *ss) {
     struct SOCK *cltss;
     struct SOCK *srvss = ss->forwardsock;

     if (!srvss) {
	  aprintf("Stray ident socket. Closing.");
	  socket_close(ss);
	  return 0;
     }

     cltss = srvss->forwardsock;
     if (!cltss) {
	  aprintf("Stray ident socket. Closing.");
	  socket_close(srvss);
	  socket_close(ss);
	  return 0;
     }

     aprintferrno("Timeout while connecting to ident port.");
     socket_close(ss);

     cltss->timeout = TIMEOUT_CONNECTED;

     if (srvss->status == STATUS_SERVERIDENT) {
	  socket_flush(srvss);
     
	  srvss->status = STATUS_SERVERCONNECTED;
	  srvss->readhandler = main_relaydata;

	  srvss->timeout = TIMEOUT_CONNECTED;
     }

     return 0;
}

/* incoming data from server in pre-relaydata status */

int main_readserver(struct SOCK *ss) {
     int inbytes;
     static char inbuffer[4096];

     struct SOCK *fs = ss->forwardsock;
     
     if (!fs) {
	  aprintf("Received serverdata for closed forwardsock.");
	  socket_close(ss);
	  return 0;
     }

     if (ss->status == STATUS_SERVERIDENT) {
	  
	  /* read data from server socket */

	  inbytes = read(ss->sockfd, inbuffer, sizeof(inbuffer));

	  if (inbytes < 0) {
	       aprintferrno("Error reading from socket fd %d", ss->sockfd);
	       socket_close(fs);
	       socket_close(ss);
	       return 0;
	  }
	  if (inbytes == 0) {
	       /* socket is closed */

	       aprintf("EOF received on fd %d", ss->sockfd);
	       socket_close(fs);
	       socket_close(ss);
	       return 0;
	  }

	  inbuffer[inbytes] = 0;

	  aprintf("Bogus data from server: %s", inbuffer);
     }
     else {
	  aprintf("Invalid status for socket %d: %d", ss->sockfd, ss->status);
     }

     return 0;
}

/* once the server connection is established this proc gets called */

int main_serverconnect(struct SOCK *ss) {
     int error;
     unsigned int len;

     struct SOCK *fs = ss->forwardsock;

     if (getsockopt(ss->sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
	  aprintf("Could not get errno from async ident socket.");
	  if (fs) socket_close(fs);
	  socket_close(ss);
	  return 0;
     }

     if (error == 0) {
	  if (fcntl(ss->sockfd, F_SETFL, ss->oldfcntlflags) != 0) {
	       aprintferrno("Cannot set server connection socket back to blocking");
	  }

	  ss->writehandler = NULL;
	  ss->readhandler = main_readserver;
	  ss->timeout = TIMEOUT_CONNECTING;
	  aprintf("Connection established. fd is %d", ss->sockfd);

	  ss->status = STATUS_SERVERIDENT;

	  if (!fs) {
	       aprintf("Error. connection to server without a client connection.\n");
	       socket_close(ss);
	       return 0	;
	  }

	  if (fs->ident) {
	       /* identing was faster than server connection */

	       socket_flush(ss);

	       ss->status = STATUS_SERVERCONNECTED;
	       ss->readhandler = main_relaydata;
	       ss->timeout = TIMEOUT_CONNECTED;
	  }

	  return 0;
     }
     else {
	  errno = error;
	  aprintferrno("Error connection to server");
	  if (fs->identsock) socket_close(fs->identsock);
	  if (fs) socket_close(fs);
	  socket_close(ss);
	  return 0;
     }
}

int main_clienthammerclose(struct SOCK *ss) {
     const char *hammertext = "421 Hammer Protection: Connection quota exceeded\n";

     write(ss->sockfd, hammertext, strlen(hammertext));
     
     socket_close(ss);
     return 0;  
}

/* Client accept handler:
   accepts a new connection through the listensocket,
   initials an async connect to the server. */

int main_acceptclient(struct SOCK *ss) {
     int newsocket;
     struct sockaddr_in	csa;
     socklen_t csa_len = sizeof(csa);
     struct SOCK *newcs;

     aprintf("Accept on fd %d", ss->sockfd);
     newsocket = accept(ss->sockfd, (struct sockaddr*)&csa, &csa_len);

     aprintf("Accepted connection from %s port %d. new fd is %d", inet_ntoa(csa.sin_addr), ntohs(csa.sin_port), newsocket);

     newcs = socklist_findunused();
     newcs->used = 1;
     socketsused++;
     newcs->sockfd = newsocket;
     newcs->readhandler = main_relaydata;
     newcs->status = STATUS_CLIENTFORWARD;
     newcs->timeout = TIMEOUT_CONNECTING;
     newcs->sockaddr = csa;

     if (!hammer_check(csa)) {
	  aprintf("Hammer Protection: Connection quota exceeded. Dropping new connection.");

	  newcs->readhandler = NULL;
	  newcs->writehandler = main_clienthammerclose;
	  return 0;
     }

     /* open nonblocking connection to main host */
     {
	  int servsock, oldopts, r;
	  struct SOCK *srvss;
	  const char *destip;

	  servsock = net_newsocket();
	  if (!net_bindsocket(servsock, config->destbindip, 0)) {
	       aprintferrno("Cannot bind to destination bindip %s", config->destbindip);
	       socket_close(newcs);
	       close(servsock);
	       return 0;
	  }

	  /* set socket to nonblocking for connect operation */
	  oldopts = fcntl(servsock, F_GETFL);
	  if (fcntl(servsock, F_SETFL, oldopts | O_NONBLOCK) != 0) {
	       aprintferrno("Cannot set server connection socket to nonblocking");
	  }
	  
	  destip = get_destinationip_cached();
	  if (!destip) {
	       aprintferrno("Cannot resolve destination hostname");
	       socket_close(newcs);
	       close(servsock);
	       return 0;
	  }
	  r = net_connect(servsock, destip, config->destport);
	  aprintf("Connecting fd %d to server at %s:%d", servsock, config->desthostname, config->destport);

	  srvss = socklist_findunused();
	  srvss->used = 1;
	  socketsused++;
	  srvss->sockfd = servsock;
	  srvss->oldfcntlflags = oldopts;
	  newcs->timeout = TIMEOUT_CONNECTING;
	  if (r == 2) {
	       srvss->writehandler = main_serverconnect;
	       srvss->status = STATUS_SERVERCONNECTING;
	  }
	  else if (r == 1) {
	       srvss->readhandler = main_relaydata;
	       srvss->status = STATUS_SERVERCONNECTED;
	  }

	  srvss->forwardsock = newcs;
	  newcs->forwardsock = srvss;
     }

     /* open an ident connection to incoming client */
     {
	  int identsock, oldopts, r;
	  struct SOCK *idtss;

	  identsock = net_newsocket();
	  if (!net_bindsocket(identsock, config->localip, 0)) {
	       aprintferrno("Cannot bind to localip %s", config->localip);
	       socket_close(newcs->forwardsock);
	       socket_close(newcs);
	       return 0;
	  }

	  /* set socket to non-blocking for connect operation */
	  oldopts = fcntl(identsock, F_GETFL);
	  if (fcntl(identsock, F_SETFL, oldopts | O_NONBLOCK) != 0) {
	       aprintferrno("Cannot set ident connection socket to non-blocking");
	  }

	  aprintf("Connecting fd %d to client ident %s:%d", identsock, inet_ntoa(newcs->sockaddr.sin_addr), IDENTD_PORT);
	  r = net_connect(identsock, inet_ntoa(newcs->sockaddr.sin_addr), IDENTD_PORT);

	  idtss = socklist_findunused();
	  idtss->used = 1;
	  socketsused++;
	  idtss->sockfd = identsock;
	  idtss->oldfcntlflags = oldopts;
	  idtss->timeout = TIMEOUT_IDENT;
	  if (r == 2) {
	       idtss->writehandler = main_identdconnect;
	       idtss->excepthandler = main_identdtimeout;
	       idtss->status = STATUS_IDENTCONNECTING;
	  }
	  else if (r == 1) {
	       idtss->readhandler = main_identdconnect;
	       idtss->status = STATUS_IDENTCONNECTED;
	  }

	  idtss->forwardsock = newcs;
	  newcs->identsock = idtss;
     }
     
     return 0;
}

/*** timeval calculation function ***/

int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
     /* Perform the carry for the later subtraction by updating y. */
     if (x->tv_usec < y->tv_usec) {
	  int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
	  y->tv_usec -= 1000000 * nsec;
	  y->tv_sec += nsec;
     }
     if (x->tv_usec - y->tv_usec > 1000000) {
	  int nsec = (y->tv_usec - x->tv_usec) / 1000000;
	  y->tv_usec += 1000000 * nsec;
	  y->tv_sec -= nsec;
     }
     
     /* Compute the time remaining to wait.
	tv_usec  is certainly positive. */
     result->tv_sec = x->tv_sec - y->tv_sec;
     result->tv_usec = x->tv_usec - y->tv_usec;
	
     /* Return 1 if result is negative. */
     return x->tv_sec < y->tv_sec;
}

/*** main select()-based dispatch loop ***/

void main_selectloop()
{
     int n, maxfd, mintimeout, r, found;
     fd_set read_selectset;
     fd_set write_selectset;
     fd_set except_selectset;
     struct timeval timer, timer2, timerdelta, selecttimeout;
     int timeouteslaped;
  
     gettimeofday(&timer, NULL);

     while(1) {

	  maxfd = 0;
	  mintimeout = 600 * TIMER_MULTIPLY;
	  FD_ZERO(&read_selectset);
	  FD_ZERO(&write_selectset);
	  FD_ZERO(&except_selectset);

	  for(n = 0; n < socketsnum; n++) {
	       if (!sockets[n]) continue;
	       if (!sockets[n]->used) continue;

	       if (sockets[n]->readhandler) FD_SET(sockets[n]->sockfd, &read_selectset);
	       if (sockets[n]->writehandler) FD_SET(sockets[n]->sockfd, &write_selectset);

	       /* catch exceptions for all sockets */
	       FD_SET(sockets[n]->sockfd, &except_selectset);

	       if (sockets[n]->sockfd + 1 > maxfd) maxfd = sockets[n]->sockfd + 1;

	       if (sockets[n]->timeout > 0 && mintimeout > sockets[n]->timeout)
		    mintimeout = sockets[n]->timeout;
	  }

	  selecttimeout.tv_sec = mintimeout / TIMER_MULTIPLY;
	  selecttimeout.tv_usec = (mintimeout % TIMER_MULTIPLY) * 1000000 / TIMER_MULTIPLY;

#ifdef DEBUG_SELECT
	  aprintf("selecting. timeout = %d", mintimeout);
#endif
	  r = select(maxfd, &read_selectset, &write_selectset, &except_selectset, &selecttimeout);

	  /* Calculate time spent in select and reduce timeouts,
	     while checking for timeout underruns */
	       
	  gettimeofday(&timer2, NULL);
	  timeval_subtract(&timerdelta, &timer2, &timer);
	       
	  timeouteslaped = (timerdelta.tv_sec * TIMER_MULTIPLY) + (timerdelta.tv_usec * TIMER_MULTIPLY / 1000000 + 1);
#ifdef DEBUG_SELECT
	  aprintf("Time %dtsec eslaped while in select.", timeouteslaped);
#endif

	  for(n = 0; n < socketsnum; n++) {
	       if (!sockets[n]) continue;
	       if (!sockets[n]->used) continue;
	       if (sockets[n]->timeout == 0) continue;

	       if (sockets[n]->timeout <= timeouteslaped) {
		    /* socket timeouted */
		    aprintf("Timeout on socket fd %d", sockets[n]->sockfd);
		    sockets[n]->timeout = 0;
			 
		    if (sockets[n]->excepthandler) {
			 sockets[n]->excepthandler(sockets[n]);
		    }
		    else { /* default on exception is to close the socket */
			 socket_close(sockets[n]);
		    }
	       }
	       else {
#ifdef DEBUG_SELECT
		    aprintf("Decreased timeout value of %d fd %d from %lu to %lu",
			    n, sockets[n]->sockfd, sockets[n]->timeout, sockets[n]->timeout - timeouteslaped);
#endif

		    sockets[n]->timeout -= timeouteslaped;
	       }
	  }
	       
	  timer = timer2;

	  /* figure out which socket got an event */

	  if (r < 0) {
	       aprintferrno("select failed");
	  }
	  else if (r == 0) {
	       aprintf("select timeout.");
	  }
	  else {
	       for(n = 0; n < socketsnum && r > 0; n++) {
		    if (!sockets[n]) continue;
		    if (!sockets[n]->used) continue;

		    found = 0;

		    if (FD_ISSET(sockets[n]->sockfd, &read_selectset) && sockets[n]->readhandler) {
			 sockets[n]->readhandler(sockets[n]);
			 found = 1;
		    }
		    if (FD_ISSET(sockets[n]->sockfd, &write_selectset) && sockets[n]->writehandler) {
			 sockets[n]->writehandler(sockets[n]);
			 found = 1;
		    }
		    if (FD_ISSET(sockets[n]->sockfd, &except_selectset)) {
			 found = 1;
			 aprintf("Exception on socket %d",sockets[n]->sockfd);
			 if (sockets[n]->excepthandler) {
			      sockets[n]->excepthandler(sockets[n]);
			 }
			 else { /* default on exception is to close the socket */
			      socket_close(sockets[n]);
			 }
		    }

		    if (found) r--;
	       }
	  }
     }
}

/*** pid file functions ***/

int main_checkpidfile(const char *pidfile)
{
     FILE *pf;
     int cpid;
     char procpidpath[256];
     char exepath[512];

     if (!pidfile || !*pidfile) return 0;

     pf = fopen(pidfile, "r");
     if (pf == NULL) {
	  printf("Cannot read pidfile %s: %s", pidfile, strerror(errno));
	  return 0;
     }

     if (fscanf(pf, "%d", &cpid) != 1) {
	  fclose(pf);
	  return 0;
     }

     fclose(pf);
     
     snprintf(procpidpath, 256, "/proc/%d/exe", cpid);

     if (readlink(procpidpath, exepath, sizeof(exepath)) <= 0) {
	  return 0;
     }

     return 1;
}

void main_writepidfile(const char *pidfile, pid_t pid)
{
     FILE *pf;

     if (!pidfile || !*pidfile) return;

     pf = fopen(pidfile, "w");
     if (pf == NULL) {
	  aprintf("Cannot create pidfile %s: %s", pidfile, strerror(errno));
	  return;
     }
     fprintf(pf, "%d", pid);
     fclose(pf);
}

/*** main program bootstrapper ***/

int main (int argc, char *argv[])
{
     int n, mypid;
     int dofork = 1;
     const char *pidfile = NULL;

     aprintf_output = 0;

     if (argc > 1) {
	  n = 1;
	  while(n < argc) {
	       if (strcmp(argv[n],"-h") == 0) {
		    printf("Usage: %s <options>\n",argv[0]);
		    printf("Options: -n = dont demonize\n");
		    printf("         -d = output debug msgs and dont demonize\n");
		    printf("         -pidfile <file> = check and write pid number to file\n");
		    return 0;
	       }
	       else if (strcmp(argv[n],"-d") == 0) {
		    dofork = 0;
		    aprintf_output = 1;
	       }
	       else if (strcmp(argv[n],"-n") == 0) {
		    dofork = 0;
	       }
	       else if (strcmp(argv[n],"-pidfile") == 0 && n+1 < argc) {
		    n++;
		    pidfile = argv[n];
	       }
	       else {
		    printf("Unknown parameter %s\n", argv[n]);
		    return 0;
	       }
	       n++;
	  }
     }    

     if (pidfile) {
	  if (main_checkpidfile(pidfile)) {
	       /* already running fine */
	       return 0;
	  }
     }

     if (!config_load()) return 1;

     printf("%s starting: config %s\n", argv[0], config->configname);

     signal(SIGINT, signal_INT);
     signal(SIGUSR1, signal_USR1);
     signal(SIGUSR2, signal_USR2);
     signal(SIGPIPE, signal_PIPE);

     {
	  int listensocket;

	  if ( (listensocket = net_newsocket()) < 0) {
	       return 1;
	  }

	  if (!net_bindsocket(listensocket, config->localip, config->localport)) {
	       printf("Cannot bind socket to %s:%d, %s\n", config->localip, config->localport, strerror(errno));
	       return 1;
	  }

	  /* go into listening mode */
	  if (listen(listensocket, SOMAXCONN) != 0) {
	       printf("Cannot listen on %s:%d, %s\n", config->localip, config->localport, strerror(errno));
	       return 1;
	  }

	  aprintf("Now listening on %s:%d", config->localip, config->localport);

	  /* insert listener socket */
	  {
	       struct SOCK *ss = socklist_findunused();
	       ss->used = 1;
	       socketsused++;
	       ss->sockfd = listensocket;
	       ss->readhandler = main_acceptclient;
	  }
     }

     if (dofork) {
	  mypid = fork();
	  if (mypid < 0) {
	       printf("First fork into background failed.\n");
	       return 0;
	  }
	  if (mypid > 0) {
	       return 0;
	  }
	  /* else drop through */

	  /* Become a process/session group leader. */
	  setsid();
	  mypid = fork();
	  if (mypid != 0) {
	       if (mypid < 0) {
		    printf("Second fork into background failed.\n");
	       }
	       return 0;
	  }

	  printf("%s forked into background as pid %d.\n", argv[0], getpid());
     }

     if (pidfile) {
	  main_writepidfile(pidfile, getpid());
     }

     if (dofork) {
	  /* Avoid keeping any directory in use. */
	  chdir("/");

	  close(0);
	  close(1);
	  close(2);
     }

     main_selectloop();

     aprintf("This should never be reached.");

     return 0;
}
