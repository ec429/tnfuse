/*
  tnfuse - FUSE client for Spectranet tnfs
  
  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags --libs` tnfuse.c -o tnfuse
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <math.h>

#include "errors.h"
#include "commands.h"
#include "config.h"
#include "flags.h"

#define min(a,b)	((a)<(b)?(a):(b))

typedef struct string
{
	char * data;
	size_t size;
}
string;

int dbg_send(int sockfd, char *data, size_t len, unsigned int flags);
int dbg_recv(int sockfd, char *data, size_t len, unsigned int flags);
void header(char *data, int cmd);
void * stackfn(void *);
inline unsigned short leshort(unsigned char * data);
inline unsigned long lelong(unsigned char * data);
void leeshort(unsigned short data, unsigned char *buf);
void leelong(unsigned long data, unsigned char *buf);

unsigned char rn;
unsigned short sessid=0;
unsigned short mintime=1000;
int fd;
char *rbox[256];
size_t rblen[256];
time_t lasttime=0;

static int tnfs_getattr(const char *path, struct stat *stbuf)
{
	// >> 0xBEEF 0x00 0x24 path(nt)
	char sdata[5+strlen(path)];
	unsigned char ern=rn;
	header(sdata, TNFS_STATFILE);
	strcpy(sdata+4, path);
	if(rbox[ern])
		free(rbox[ern]);
	rbox[ern]=NULL;
	dbg_send(fd, sdata, 5+strlen(path), 0);
	while(rbox[ern]==NULL)
	{
		usleep(25000); // lazily done delay-spin-loop
	}
	// << 0xBEEF 0x00 0x24 status(1) mode(2) uid(2) gid(2) size(4) atime(4) mtime(4) ctime(4) uidstring(nt) gidstring(nt)
	unsigned short rsessid = *(unsigned short *)rbox[ern];
	if(rsessid!=sessid)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		fprintf(stderr, "tnfuse: getattr: sessid mismatch.  EIO\n");
		return(-EIO);
	}
	unsigned char rrn=rbox[ern][2];
	if(rrn!=ern)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		fprintf(stderr, "tnfuse: getattr: rrn/ern mismatch.  EIO\n");
		return(-EIO);
	}
	unsigned char cmd=rbox[ern][3];
	if(cmd!=TNFS_STATFILE)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		fprintf(stderr, "tnfuse: getattr: cmd mismatch.  EIO\n");
		return(-EIO);
	}
	unsigned char status=rbox[ern][4];
	if(status!=TNFS_SUCCESS)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		if(status<TNFS_E_MAX)
		{
			fprintf(stderr, "tnfuse: getattr: error %02x->%d, %s\n", status, err_to_sys[status], strerror(err_to_sys[status]));
			return(-err_to_sys[status]);
		}
		else
		{
			fprintf(stderr, "tnfuse: getattr: error %02x.  EIO\n", status);
			return(-EIO);
		}
	}
	stbuf->st_mode	= leshort((unsigned char *)rbox[ern]+5);
	stbuf->st_uid	= leshort((unsigned char *)rbox[ern]+7);
	stbuf->st_gid	= leshort((unsigned char *)rbox[ern]+9);
	stbuf->st_size	= lelong((unsigned char *)rbox[ern]+11);
	stbuf->st_atime	= lelong((unsigned char *)rbox[ern]+15);
	stbuf->st_mtime	= lelong((unsigned char *)rbox[ern]+19);
	stbuf->st_ctime	= lelong((unsigned char *)rbox[ern]+23);
	// We don't care about [u|g]idstring for now
	// this could cause issues as the uid/gid will be checked against the local /etc/passwd instead of the remote one
	// but it's not obvious how to do this correctly
	free(rbox[ern]);
	rbox[ern]=NULL;
	fprintf(stderr, "tnfuse: getattr: OK\n");
	return(0);
}

static int tnfs_access(const char *path, int mask)
{
	fprintf(stderr, "tnfuse: access: ENOSYS (use -o default_permissions instead)\n");
	return(-ENOSYS);
}

static int tnfs_readlink(const char *path, char *buf, size_t size)
{
	fprintf(stderr, "tnfuse: readlink: ENOSYS\n");
	return(-ENOSYS);
}


static int tnfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	// >> 0xBEEF 0x00 0x10 path(nt) - Open absolute path
	char sdata[5+strlen(path)];
	unsigned char ern=rn;
	header(sdata, TNFS_OPENDIR);
	strcpy(sdata+4, path);
	if(rbox[ern])
		free(rbox[ern]);
	rbox[ern]=NULL;
	dbg_send(fd, sdata, 5+strlen(path), 0);
	while(rbox[ern]==NULL)
	{
		usleep(25000); // lazily done delay-spin-loop
	}
	// << 0xBEEF 0x00 0x10 0x00 handle(1) - success, handle provided
	unsigned short rsessid = *(unsigned short *)rbox[ern];
	if(rsessid!=sessid)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		fprintf(stderr, "tnfuse: readdir: sessid mismatch.  EIO\n");
		return(-EIO);
	}
	unsigned char rrn=rbox[ern][2];
	if(rrn!=ern)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		fprintf(stderr, "tnfuse: readdir: rrn/ern mismatch.  EIO\n");
		return(-EIO);
	}
	unsigned char cmd=rbox[ern][3];
	if(cmd!=TNFS_OPENDIR)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		fprintf(stderr, "tnfuse: readdir: cmd mismatch.  EIO\n");
		return(-EIO);
	}
	unsigned char status=rbox[ern][4];
	if(status!=TNFS_SUCCESS)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		if(status<TNFS_E_MAX)
		{
			fprintf(stderr, "tnfuse: readdir: error %02x->%d, %s\n", status, err_to_sys[status], strerror(err_to_sys[status]));
			return(-err_to_sys[status]);
		}
		else
		{
			fprintf(stderr, "tnfuse: readdir: error %02x.  EIO\n", status);
			return(-EIO);
		}
	}
	unsigned char handle=rbox[ern][5];
	
	int errupt=0;
	while(!errupt)
	{
		// >> 0xBEEF 0x00 0x11 handle(1) - read an entry from directory handle
		ern=rn;
		header(sdata, TNFS_READDIR);
		sdata[4]=handle;
		if(rbox[ern])
			free(rbox[ern]);
		rbox[ern]=NULL;
		dbg_send(fd, sdata, 5, 0);
		while(rbox[ern]==NULL)
		{
			usleep(25000); // lazily done delay-spin-loop
		}
		// << 0xBEEF 0x00 0x11 name(nt) - directory entry OR
		// << 0xBEEF 0x00 0x11 0x00 ERR - error
		rsessid = *(unsigned short *)rbox[ern];
		if(rsessid!=sessid)
		{
			free(rbox[ern]);
			rbox[ern]=NULL;
			fprintf(stderr, "tnfuse: readdir: sessid mismatch.  EIO\n");
			return(-EIO);
		}
		rrn=rbox[ern][2];
		if(rrn!=ern)
		{
			free(rbox[ern]);
			rbox[ern]=NULL;
			fprintf(stderr, "tnfuse: readdir: rrn/ern mismatch.  EIO\n");
			return(-EIO);
		}
		cmd=rbox[ern][3];
		if(cmd!=TNFS_READDIR)
		{
			free(rbox[ern]);
			rbox[ern]=NULL;
			fprintf(stderr, "tnfuse: readdir: cmd mismatch.  EIO\n");
			return(-EIO);
		}
		status=rbox[ern][4];
		switch(status)
		{
			case TNFS_SUCCESS:
				if(filler(buf, rbox[ern]+5, NULL, 0)!=0) // assuming that filler strdup()s name for you
					return(-ENOMEM);
			break;
			case TNFS_EOF:
				errupt++;
			break;
			default:
				if(status<TNFS_E_MAX)
				{
					fprintf(stderr, "tnfuse: readdir: error %02x -> %d, %s\n", status, err_to_sys[status], strerror(err_to_sys[status]));
					return(-err_to_sys[status]);
				}
				else
				{
					fprintf(stderr, "tnfuse: readdir: error %02x.  EIO\n", status);
					return(-EIO);
				}
				errupt++;
			break;
		}
		free(rbox[ern]);
		rbox[ern]=NULL;
	}
	// >> 0xBEEF 0x00 0x12 handle(1) - Close the directory handle
	ern=rn;
	header(sdata, TNFS_CLOSEDIR);
	sdata[4]=handle;
	if(rbox[ern])
		free(rbox[ern]);
	rbox[ern]=NULL;
	dbg_send(fd, sdata, 5, 0);
	return(0);
}

static int tnfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	fprintf(stderr, "tnfuse: mknod: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_mkdir(const char *path, mode_t mode)
{
	fprintf(stderr, "tnfuse: mkdir: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_rmdir(const char *path)
{
	fprintf(stderr, "tnfuse: rmdir: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_symlink(const char *from, const char *to)
{
	fprintf(stderr, "tnfuse: symlink: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_unlink(const char *path)
{
	fprintf(stderr, "tnfuse: unlink: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_rename(const char *from, const char *to)
{
	fprintf(stderr, "tnfuse: rename: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_link(const char *from, const char *to)
{
	fprintf(stderr, "tnfuse: link: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_chmod(const char *path, mode_t mode)
{
	fprintf(stderr, "tnfuse: chmod: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_chown(const char *path, uid_t uid, gid_t gid)
{
	fprintf(stderr, "tnfuse: chown: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_truncate(const char *path, off_t size)
{
	fprintf(stderr, "tnfuse: truncate: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_utimens(const char *path, const struct timespec ts[2])
{
	fprintf(stderr, "tnfuse: utimens: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_open(const char *path, struct fuse_file_info *fi)
{
	// >> 0xBEEF 0x00 0x20 mode(1) flags(1) path(nt) - Open file at absolute path
	unsigned char mode=0;
	if((fi->flags & O_RDONLY) == O_RDONLY)
		mode|=TNFS_O_RDONLY;
	if((fi->flags & O_WRONLY) == O_WRONLY)
		mode|=TNFS_O_WRONLY;
	if((fi->flags & O_RDWR) == O_RDWR)
		mode|=TNFS_O_RDWR;
	if(mode==0)
	{
		fprintf(stderr, "tnfuse: open: invalid oflag. EINVAL\n");
		return(-EINVAL);
	}
	unsigned char flags=0;
	if(fi->flags & O_APPEND)
		flags|=TNFS_O_APPEND;
	if(fi->flags & O_CREAT)
		flags|=TNFS_O_CREAT;
	if(fi->flags & O_EXCL)
		flags|=TNFS_O_EXCL;
	if(fi->flags & O_TRUNC)
		flags|=TNFS_O_TRUNC;
	char sdata[7+strlen(path)];
	unsigned char ern=rn;
	header(sdata, TNFS_OPENFILE);
	sdata[4]=mode;
	sdata[5]=flags;
	strcpy(sdata+6, path);
	if(rbox[ern])
		free(rbox[ern]);
	rbox[ern]=NULL;
	dbg_send(fd, sdata, 7+strlen(path), 0);
	while(rbox[ern]==NULL)
	{
		usleep(25000); // lazily done delay-spin-loop
	}
	// << 0xBEEF 0x00 0x20 status(1) [fd(1)]
	unsigned short rsessid = *(unsigned short *)rbox[ern];
	if(rsessid!=sessid)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		fprintf(stderr, "tnfuse: open: sessid mismatch.  EIO\n");
		return(-EIO);
	}
	unsigned char rrn=rbox[ern][2];
	if(rrn!=ern)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		fprintf(stderr, "tnfuse: open: rrn/ern mismatch.  EIO\n");
		return(-EIO);
	}
	unsigned char cmd=rbox[ern][3];
	if(cmd!=TNFS_OPENFILE)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		fprintf(stderr, "tnfuse: open: cmd mismatch.  EIO\n");
		return(-EIO);
	}
	unsigned char status=rbox[ern][4];
	if(status!=TNFS_SUCCESS)
	{
		free(rbox[ern]);
		rbox[ern]=NULL;
		if(status<TNFS_E_MAX)
		{
			fprintf(stderr, "tnfuse: open: error %02x->%d, %s\n", status, err_to_sys[status], strerror(err_to_sys[status]));
			return(-err_to_sys[status]);
		}
		else
		{
			fprintf(stderr, "tnfuse: open: error %02x.  EIO\n", status);
			return(-EIO);
		}
	}
	else
	{
		unsigned char fd=rbox[ern][5];
		fi->fh=fd;
		return(0);
	}
}

static int tnfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	size_t bytes=0;
	while(bytes<size)
	{
		// >> 0xBEEF 0x00 0x21 fd(1) size(2le)
		char sdata[7];
		unsigned char ern=rn;
		header(sdata, TNFS_READBLOCK);
		sdata[4]=fi->fh;
		leeshort(size-bytes, sdata+5);
		if(rbox[ern])
			free(rbox[ern]);
		rbox[ern]=NULL;
		dbg_send(fd, sdata, 7, 0);
		while(rbox[ern]==NULL)
		{
			usleep(25000); // lazily done delay-spin-loop
		}
		// << 0xBEEF 0x00 0x21 status(1) [size(2le) data(size)]
		unsigned short rsessid = *(unsigned short *)rbox[ern];
		if(rsessid!=sessid)
		{
			free(rbox[ern]);
			rbox[ern]=NULL;
			fprintf(stderr, "tnfuse: read: sessid mismatch.  EIO\n");
			return(-EIO);
		}
		unsigned char rrn=rbox[ern][2];
		if(rrn!=ern)
		{
			free(rbox[ern]);
			rbox[ern]=NULL;
			fprintf(stderr, "tnfuse: read: rrn/ern mismatch.  EIO\n");
			return(-EIO);
		}
		unsigned char cmd=rbox[ern][3];
		if(cmd!=TNFS_READBLOCK)
		{
			free(rbox[ern]);
			rbox[ern]=NULL;
			fprintf(stderr, "tnfuse: read: cmd mismatch.  EIO\n");
			return(-EIO);
		}
		unsigned char status=rbox[ern][4];
		if(status!=TNFS_SUCCESS)
		{
			free(rbox[ern]);
			rbox[ern]=NULL;
			if(status==TNFS_EOF)
			{
				size=0;
			}
			else if(status<TNFS_E_MAX)
			{
				fprintf(stderr, "tnfuse: read: error %02x->%d, %s\n", status, err_to_sys[status], strerror(err_to_sys[status]));
				return(-err_to_sys[status]);
			}
			else
			{
				fprintf(stderr, "tnfuse: read: error %02x.  EIO\n", status);
				return(-EIO);
			}
		}
		else
		{
			unsigned short length=leshort(rbox[ern]+5);
			if(bytes+length>size)
			{
				fprintf(stderr, "tnfuse: read: warning - long count returned by server\n");
			}
			memcpy(buf+bytes, rbox[ern]+7, min(length, size-bytes));
			bytes+=length;
		}
	}
	return(bytes);
}

static int tnfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	fprintf(stderr, "tnfuse: write: ENOSYS\n");
	return(-ENOSYS);
}

static int tnfs_statfs(const char *path, struct statvfs *stbuf)
{
	fprintf(stderr, "tnfuse: statfs: ENOSYS\n");
	return(-ENOSYS);
}

static struct fuse_operations tnfs_oper = {
	.getattr	= tnfs_getattr,
	.access		= tnfs_access,
	.readlink	= tnfs_readlink,
	.readdir	= tnfs_readdir,
	.mknod		= tnfs_mknod,
	.mkdir		= tnfs_mkdir,
	.symlink	= tnfs_symlink,
	.unlink		= tnfs_unlink,
	.rmdir		= tnfs_rmdir,
	.rename		= tnfs_rename,
	.link		= tnfs_link,
	.chmod		= tnfs_chmod,
	.chown		= tnfs_chown,
	.truncate	= tnfs_truncate,
	.utimens	= tnfs_utimens,
	.open		= tnfs_open,
	.read		= tnfs_read,
	.write		= tnfs_write,
	.statfs		= tnfs_statfs,
};

int main(int argc, char *argv[])
{
	umask(0);
	
	/* Parse args */
	unsigned short port=TNFSD_PORT;
	char *host;
	char *remote_dir;
	if(argc<3)
	{
		fprintf(stderr, "Usage: tnfuse <hostname>[:port] <remote-dir> <mountpoint> [options]\n");
		return(1);
	}
	host=strdup(argv[1]);
	char *colon = strchr(host, ':');
	if(colon!=NULL)
	{
		fprintf(stderr, "alternate ports not done yet!\n");
		return(1);
	}
	char sport[6];
	sprintf(sport, "%u", port);
	
	remote_dir=argv[2];
	
	int fargc=argc-2;
	char **fargv=(char **)malloc(fargc*sizeof(char *));
	int i;
	fargv[0]=argv[0];
	printf("%s (%d)\n", fargv[0], fargc);
	for(i=1;i<fargc;i++)
	{
		fargv[i]=argv[i+2];
		printf("%s\n", fargv[i]);
	}
	
	memset(rbox, 0, sizeof(rbox));
	memset(rblen, 0, sizeof(rblen));
	
	/* Lookup host */
	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
	struct addrinfo *info;
	int e;
	if((e=getaddrinfo(host, sport, &hints, &info))!=0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(e));
		return(2);
	}
	
	/* MOUNT */
	/* Open a UDP socket, and issue the mount cmd.  Also gets a session ID */
	
	rn=0;
	char sip[INET_ADDRSTRLEN];
	struct addrinfo *p;
	int serverhandle;
	// loop through all the results and open a socket for the first we can
	for(p = info; p != NULL; p = p->ai_next)
	{
		inet_ntop(p->ai_family, &(((struct sockaddr_in*)p->ai_addr)->sin_addr), sip, sizeof(sip));
		printf("tnfuse: connecting to %s\n", sip);
		if((serverhandle = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
		{
			perror("tnfuse: socket");
			continue;
		}
		if(connect(serverhandle, p->ai_addr, p->ai_addrlen) == -1)
		{
			close(serverhandle);
			perror("tnfuse: connect");
			continue;
		}
		break;
	}
	if(p==NULL)
	{
		fprintf(stderr, "tnfuse: failed to connect\n");
		return(2);
	}
	freeaddrinfo(info);
	
	fprintf(stderr, "tnfuse: mounting %s under %s\n", remote_dir, fargv[1]);

	char sdata[9+strlen(remote_dir)];
	int ern=rn;
	header(sdata, TNFS_MOUNT);
	sdata[4]=PROTOVERSION_LSB;
	sdata[5]=PROTOVERSION_MSB;
	sprintf(sdata+6, "%s%c%c", remote_dir, 0, 0);
	dbg_send(serverhandle, sdata, 9+strlen(remote_dir), 0);
	
	char rdata[9];
	dbg_recv(serverhandle, rdata, 9, 0);
	sessid=*(unsigned short *)rdata;
	char seqnum=rdata[2];
	if(seqnum!=ern)
	{
		fprintf(stderr, "tnfuse: bad retry number %02x, expected %02x\n", seqnum, ern);
		return(3);
	}
	char cmd=rdata[3];
	if(cmd!=TNFS_MOUNT)
	{
		fprintf(stderr, "tnfuse: bad cmd %02x, expected %02x\n", cmd, TNFS_MOUNT);
		return(3);
	}
	char status=rdata[4];
	char lver=rdata[5],mver=rdata[6];
	if(status!=0)
	{
		fprintf(stderr, "tnfuse: failed to mount (tnfs error %02x, server version %hhu.%hhu)\n", status, mver, lver);
		return(3);
	}
	
	fprintf(stderr, "tnfuse: Session ID is %04x, server is %hhu.%hhu\n", sessid, mver, lver);
	mintime=*(unsigned short *)(rdata+7);
	fprintf(stderr, "tnfuse: min. retry time is %hums\n", mintime);
	fd=serverhandle;
	
	int rv=0;
	
	fprintf(stderr, "Starting stack...\n");
	pthread_t stackthread;
	pthread_attr_t stackattr;
	pthread_attr_init(&stackattr);
	if(pthread_create(&stackthread, &stackattr, stackfn, NULL))
	{
		fprintf(stderr, "Failed to start stack thread!\n");
		perror("pthread_create");
		rv=4;
	}
	else
	{
		fprintf(stderr, "stack started\n");

		fprintf(stderr, "tnfuse client daemon now active\n");
	
		rv=fuse_main(fargc, fargv, &tnfs_oper, NULL);
	}
	fprintf(stderr, "tnfuse: umounting remote tnfs under %s\n", fargv[1]);
	char udata[4];
	header(udata, TNFS_UMOUNT);
	dbg_send(serverhandle, udata, 4, 0);
	close(serverhandle);
	fprintf(stderr, "tnfuse client daemon shutting down\n");
	return(rv);
}

int dbg_send(int sockfd, char *data, size_t len, unsigned int flags)
{
#ifdef DELAY
	while(time(NULL)<lasttime+ceil(mintime/1000.0));
#endif
	size_t bytes=send(sockfd, data, len, flags);
#ifdef DEBUG
	printf(">> ");
	int i;
	for(i=0;i<len;i++)
	{
		if(i==bytes)
			printf("|| ");
		printf("%02x ", (unsigned char) data[i]);
	}
	if(len>bytes)
		printf("||");
	else
		printf(">>");
	printf("\n");
#endif
	lasttime=time(NULL);
	return(bytes);
}

int dbg_recv(int sockfd, char *data, size_t len, unsigned int flags)
{
	size_t bytes=recv(sockfd, data, len, flags);
#ifdef DEBUG
	printf("<< ");
	int i;
	for(i=0;i<bytes;i++)
	{
		printf("%02x ", (unsigned char) data[i]);
	}
	printf("<<\n");
#endif
	return(bytes);
}

void header(char *data, int cmd)
{
	data[0]=sessid%256; // SESSION ID, LSB
	data[1]=sessid>>8; // SESSION ID, MSB
	data[2]=rn;rn=(unsigned char)(rn+1);
	data[3]=(char)cmd;
}

void *stackfn(void *unused)
{
	while(true)
	{
		char rdata[MAXMSGSZ];
		size_t bytes=dbg_recv(fd, rdata, MAXMSGSZ, 0);
		unsigned short rsessid=*(unsigned short *)rdata;
		if(rsessid!=sessid)
		{
			fprintf(stderr, "tnfuse: stackfn: packet not meant for us!\n");
		}
		else
		{
			unsigned char rrn=rdata[2];
			if(rbox[rrn])
				free(rbox[rrn]);
			rblen[rrn]=bytes;
			rbox[rrn]=(char *)malloc(bytes);
			memcpy(rbox[rrn], rdata, bytes);
		}
	}
}

inline unsigned short leshort(unsigned char * data)
{
	return(data[0]+(data[1]<<8));
}

inline unsigned long lelong(unsigned char * data)
{
	return(data[0]+(data[1]<<8)+(data[2]<<16)+(data[3]<<24));
}

void leeshort(unsigned short data, unsigned char *buf)
{
	buf[1]=(data>>8)%(1<<8);
	buf[0]=data%(1<<8);
}

void leelong(unsigned long data, unsigned char *buf)
{
	buf[3]=(data>>24)%(1<<8);
	buf[2]=(data>>16)%(1<<8);
	buf[1]=(data>>8)%(1<<8);
	buf[0]=data%(1<<8);
}
