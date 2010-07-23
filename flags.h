/* tnfs versions of POSIX flags */
#define TNFS_O_RDONLY	0x01
#define TNFS_O_WRONLY	0x02
#define TNFS_O_RDWR		(TNFS_O_RDONLY|TNFS_O_WRONLY)

#define TNFS_O_APPEND	0x01
#define TNFS_O_CREAT	0x02
#define TNFS_O_EXCL		0x04
#define TNFS_O_TRUNC	0x08
