// Error table from tnfsd errortable.h, and table to convert to POSIX equivalents
#include <errno.h>

#define TNFS_SUCCESS	0x00
#define TNFS_EPERM	0x01
#define TNFS_ENOENT	0x02
#define TNFS_EIO	0x03
#define TNFS_ENXIO	0x04
#define TNFS_E2BIG	0x05
#define TNFS_EBADF	0x06
#define TNFS_EAGAIN	0x07
#define TNFS_ENOMEM	0x08
#define TNFS_EACCES	0x09
#define TNFS_EBUSY	0x0A
#define TNFS_EEXIST	0x0B
#define TNFS_ENOTDIR	0x0C
#define TNFS_EISDIR	0x0D
#define TNFS_EINVAL	0x0E
#define TNFS_ENFILE	0x0F
#define TNFS_EMFILE	0x10
#define TNFS_EFBIG	0x11
#define TNFS_ENOSPC	0x12
#define TNFS_ESPIPE	0x13
#define TNFS_EROFS	0x14
#define TNFS_ENAMETOOLONG 0x15
#define TNFS_ENOSYS	0x16
#define TNFS_ENOTEMPTY	0x17
#define TNFS_ELOOP	0x18
#define TNFS_ENODATA	0x19
#define TNFS_ENOSTR	0x1A
#define TNFS_EPROTO	0x1B
#define TNFS_EBADFD	0x1C
#define TNFS_EUSERS	0x1D
#define TNFS_ENOBUFS	0x1E
#define TNFS_EALREADY	0x1F
#define TNFS_ESTALE	0x20
#define TNFS_EOF	0x21 // converts as EIO as it's not a POSIX errno

#define TNFS_E_MAX	0x22	// one more than largest error code

int err_to_sys[]={0, EPERM, ENOENT, EIO, ENXIO, E2BIG, EBADF, EAGAIN, ENOMEM, EACCES, EBUSY, EEXIST, ENOTDIR, EISDIR, EINVAL, ENFILE, EMFILE, EFBIG, ENOSPC, ESPIPE, EROFS, ENAMETOOLONG, ENOSYS, ENOTEMPTY, ELOOP, ENODATA, ENOSTR, EPROTO, EBADFD, EUSERS, ENOBUFS, EALREADY, ESTALE, EIO};
