/* tnfs versions of POSIX flags */
// open() oflag
#define TNFS_O_RDONLY	0x01
#define TNFS_O_WRONLY	0x02
#define TNFS_O_RDWR		(TNFS_O_RDONLY|TNFS_O_WRONLY)

// open() mode
#define TNFS_O_APPEND	0x01
#define TNFS_O_CREAT	0x02
#define TNFS_O_EXCL		0x04
#define TNFS_O_TRUNC	0x08

// lseek() type
#define TNFS_SEEK_SET	0x00
#define TNFS_SEEK_CUR	0x01
#define TNFS_SEEK_END	0x02
