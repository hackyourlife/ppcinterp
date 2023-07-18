#ifndef __NANOLIBC_H__
#define __NANOLIBC_H__

// nanolibc: implementation of various posix functions/syscall wrappers

#define _GNU_SOURCE
//#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
//#include <fcntl.h>
//#include <stdio.h>
//#include <errno.h>
#include <sys/uio.h>
#include <sys/utsname.h>
//#include <sys/syscall.h>

#if defined(__x86_64__)
#define LONG64		1
#define	PTRSZ		uint64_t

#define	SYS_exit	60
#define	SYS_read	0
#define	SYS_write	1
#define	SYS_open	2
#define	SYS_close	3
#define	SYS_lseek	8
#define	SYS_mmap	9
#define SYS_mprotect	10
#define	SYS_munmap	11
#define	SYS_uname	63
#define	SYS_mkdir	83
#define	SYS_rmdir	84
#define	SYS_getuid	102
#define	SYS_getgid	104
#define	SYS_geteuid	107
#define	SYS_getegid	108
#elif defined(__powerpc__)
#define LONG32		1
#define	PTRSZ		uint32_t

#define	SYS_exit	1
#define	SYS_read	3
#define	SYS_write	4
#define	SYS_open	5
#define	SYS_close	6
#define	SYS_lseek	19
#define	SYS_getuid	24
#define	SYS_mkdir	39
#define	SYS_rmdir	40
#define	SYS_getgid	47
#define	SYS_geteuid	49
#define	SYS_getegid	50
#define	SYS_mmap	90
#define	SYS_munmap	91
#define SYS_uname	122
#define SYS_mprotect	125
#else
#error "Unsupported architecture"
#endif


// avoid name conflicts
#define	getcwd	__nanolibc_getcwd
#define	read	__nanolibc_read
#define	write	__nanolibc_write
#define	open	__nanolibc_open
#define	close	__nanolibc_close
#define	lseek	__nanolibc_lseek
#define	readv	__nanolibc_readv
#define	writev	__nanolibc_writev
#define	exit	__nanolibc_exit
#define	_Exit	__nanolibc_exit_group
#define	mkdir	__nanolibc_mkdir
#define	rmdir	__nanolibc_rmdir
#define	uname	__nanolibc_uname
#define	getuid	__nanolibc_getuid
#define	getgid	__nanolibc_getgid
#define	mmap	__nanolibc_mmap
#define	munmap	__nanolibc_munmap
#define	syscall	__syscall

#define	strlen	__nanolibc_strlen
#define	memset	__nanolibc_memset
#define	malloc	__nanolibc_malloc
#define	free	__nanolibc_free

#ifdef errno
#undef errno
#endif
#define	errno __nanolibc_errno

extern int errno;

#define	asm __asm__
#define	inline __inline__

#define	__ssc(x) ((PTRSZ) (x))

#define	NULL		((void *) 0)
#define	O_RDONLY	00000000

#define	MAP_FAILED	((void *) -1)

#define	PROT_NONE	0x0
#define	PROT_READ	0x1
#define	PROT_WRITE	0x2
#define	PROT_EXEC	0x4

#define	MAP_SHARED	0x01
#define	MAP_PRIVATE	0x02
#define	MAP_TYPE	0x0f
#define	MAP_FIXED	0x10
#define	MAP_ANONYMOUS	0x20

#define	SEEK_SET	0
#define	SEEK_CUR	1
#define	SEEK_END	2

#define	EBADF		9
#define	EINVAL		22
#define	ENOSYS		38

// syscall helpers
//
#ifdef __x86_64__
static inline long __syscall0(long id)
{
	long result;
	__asm__ volatile("syscall" : "=a"(result)
				   : "a"(id)
				   : "memory", "rcx", "r11");
	return result;
}

static inline long __syscall1(long id, long a1)
{
	long result;
	__asm__ volatile("syscall" : "=a"(result)
				   : "a"(id), "D"(a1)
				   : "memory", "rcx", "r11");
	return result;
}

static inline long __syscall2(long id, long a1, long a2)
{
	long result;
	__asm__ volatile("syscall" : "=a"(result)
				   : "a"(id), "D"(a1), "S"(a2)
				   : "memory", "rcx", "r11");
	return result;
}

static inline long __syscall3(long id, long a1, long a2, long a3)
{
	long result;
	__asm__ volatile("syscall" : "=a"(result)
				   : "a"(id), "D"(a1), "S"(a2), "d"(a3)
				   : "memory", "rcx", "r11");
	return result;
}

static inline long __syscall6(long id, long a1, long a2, long a3, long a4,
		long a5, long a6)
{
	long result;
	register int64_t r10 asm("r10") = a4;
	register int64_t r8 asm("r8") = a5;
	register int64_t r9 asm("r9") = a6;
	__asm__ volatile("syscall" : "=a"(result)
				   : "a"(id), "D"(a1), "S"(a2), "d"(a3),
				     "r"(r10), "r"(r8), "r"(r9)
				   : "memory", "rcx", "r11");
	return result;
}
#elif defined(__powerpc__)
static inline long __syscall0(long n)
{
	register long r0 __asm__("r0") = n;
	register long r3 __asm__("r3");
	__asm__ __volatile__("sc ; bns+ 1f ; neg %1, %1 ; 1:"
	: "+r"(r0), "=r"(r3)
	:: "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12");
	return r3;
}

static inline long __syscall1(long n, long a)
{
	register long r0 __asm__("r0") = n;
	register long r3 __asm__("r3") = a;
	__asm__ __volatile__("sc ; bns+ 1f ; neg %1, %1 ; 1:"
	: "+r"(r0), "+r"(r3)
	:: "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12");
	return r3;
}

static inline long __syscall2(long n, long a, long b)
{
	register long r0 __asm__("r0") = n;
	register long r3 __asm__("r3") = a;
	register long r4 __asm__("r4") = b;
	__asm__ __volatile__("sc ; bns+ 1f ; neg %1, %1 ; 1:"
	: "+r"(r0), "+r"(r3), "+r"(r4)
	:: "memory", "cr0", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12");
	return r3;
}

static inline long __syscall3(long n, long a, long b, long c)
{
	register long r0 __asm__("r0") = n;
	register long r3 __asm__("r3") = a;
	register long r4 __asm__("r4") = b;
	register long r5 __asm__("r5") = c;
	__asm__ __volatile__("sc ; bns+ 1f ; neg %1, %1 ; 1:"
	: "+r"(r0), "+r"(r3), "+r"(r4), "+r"(r5)
	:: "memory", "cr0", "r6", "r7", "r8", "r9", "r10", "r11", "r12");
	return r3;
}

static inline long __syscall4(long n, long a, long b, long c, long d)
{
	register long r0 __asm__("r0") = n;
	register long r3 __asm__("r3") = a;
	register long r4 __asm__("r4") = b;
	register long r5 __asm__("r5") = c;
	register long r6 __asm__("r6") = d;
	__asm__ __volatile__("sc ; bns+ 1f ; neg %1, %1 ; 1:"
	: "+r"(r0), "+r"(r3), "+r"(r4), "+r"(r5), "+r"(r6)
	:: "memory", "cr0", "r7", "r8", "r9", "r10", "r11", "r12");
	return r3;
}

static inline long __syscall5(long n, long a, long b, long c, long d, long e)
{
	register long r0 __asm__("r0") = n;
	register long r3 __asm__("r3") = a;
	register long r4 __asm__("r4") = b;
	register long r5 __asm__("r5") = c;
	register long r6 __asm__("r6") = d;
	register long r7 __asm__("r7") = e;
	__asm__ __volatile__("sc ; bns+ 1f ; neg %1, %1 ; 1:"
	: "+r"(r0), "+r"(r3), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(r7)
	:: "memory", "cr0", "r8", "r9", "r10", "r11", "r12");
	return r3;
}

static inline long __syscall6(long n, long a, long b, long c, long d, long e, long f)
{
	register long r0 __asm__("r0") = n;
	register long r3 __asm__("r3") = a;
	register long r4 __asm__("r4") = b;
	register long r5 __asm__("r5") = c;
	register long r6 __asm__("r6") = d;
	register long r7 __asm__("r7") = e;
	register long r8 __asm__("r8") = f;
	__asm__ __volatile__("sc ; bns+ 1f ; neg %1, %1 ; 1:"
	: "+r"(r0), "+r"(r3), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(r7), "+r"(r8)
	:: "memory", "cr0", "r9", "r10", "r11", "r12");
	return r3;
}
#endif

#define __SYSCALL_0(n) \
	__syscall0(__ssc(n));

#define __SYSCALL_1(n, a) \
	__syscall1(__ssc(n), __ssc(a));

#define __SYSCALL_2(n, a, b) \
	__syscall2(__ssc(n), __ssc(a), __ssc(b));

#define __SYSCALL_3(n, a, b, c) \
	__syscall3(__ssc(n), __ssc(a), __ssc(b), __ssc(c));

#define __SYSCALL_4(n, a, b, c, d) \
	__syscall4(__ssc(n), __ssc(a), __ssc(b), __ssc(c), __ssc(d));

#define __SYSCALL_5(n, a, b, c, d, e) \
	__syscall5(__ssc(n), __ssc(a), __ssc(b), __ssc(c), __ssc(d), __ssc(e));

#define __SYSCALL_6(n, a, b, c, d, e, f) \
	__syscall6(__ssc(n), __ssc(a), __ssc(b), __ssc(c), __ssc(d), __ssc(e), __ssc(f));

#define __SYSCALL_RET(result) { \
	if(result < 0) { \
		errno = -result; \
		return -1; \
	} \
	return result; \
}

#define __SYSCALL_0P(id) { \
	long result = __SYSCALL_0(id); \
	__SYSCALL_RET(result); \
}

#define __SYSCALL_1P(id, a1) { \
	long result = __SYSCALL_1(id, a1); \
	__SYSCALL_RET(result); \
}

#define __SYSCALL_2P(id, a1, a2) { \
	long result = __SYSCALL_2(id, a1, a2); \
	__SYSCALL_RET(result); \
}

#define __SYSCALL_3P(id, a1, a2, a3) { \
	long result = __SYSCALL_3(id, a1, a2, a3); \
	__SYSCALL_RET(result); \
}

#define __SYSCALL_6P(id, a1, a2, a3, a4, a5, a6) { \
	long result = __SYSCALL_6(id, a1, a2, a3, a4, a5, a6); \
	__SYSCALL_RET(result); \
}

long syscall(long number, ...);

// posix/libc functions
static inline ssize_t read(int fd, void *buf, size_t count)
{
	__SYSCALL_3P(SYS_read, fd, buf, count);
}

static inline ssize_t write(int fd, const void *buf, size_t count)
{
	__SYSCALL_3P(SYS_write, fd, buf, count);
}

static inline int open(const char *filename, int flags, ...)
{
	va_list args;
	va_start(args, flags);
	__SYSCALL_3P(SYS_open, filename, flags, va_arg(args, mode_t));
	va_end(args);
}

static inline int close(int fd)
{
	__SYSCALL_1P(SYS_close, fd);
}

static inline long lseek(int fd, off_t offset, int whence)
{
	__SYSCALL_3P(SYS_lseek, fd, offset, whence);
}

#if 0
static inline ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	__SYSCALL_3P(SYS_readv, fd, iov, iovcnt);
}

static inline ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	__SYSCALL_3P(SYS_writev, fd, iov, iovcnt);
}

static inline char *getcwd(char *buf, size_t size)
{
	int64_t result = __SYSCALL_2(SYS_getcwd, buf, size);
	if(result < 0) {
		errno = -result;
		return NULL;
	}
	return buf;
}

static inline void _Exit(int ec)
{
	__SYSCALL_1(SYS_exit_group, ec);
}
#endif

static inline void exit(int ec)
{
	__SYSCALL_1(SYS_exit, ec);
}

static inline int mkdir(const char *path, mode_t mode)
{
	__SYSCALL_2P(SYS_mkdir, path, mode);
}

static inline int rmdir(const char *path, mode_t mode)
{
	__SYSCALL_2P(SYS_rmdir, path, mode);
}

static inline int uname(struct utsname *buf)
{
	__SYSCALL_1P(SYS_uname, buf);
}

static inline int getuid(void)
{
	__SYSCALL_0P(SYS_getuid);
}

static inline int getgid(void)
{
	__SYSCALL_0P(SYS_getgid);
}

static inline int geteuid(void)
{
	__SYSCALL_0P(SYS_geteuid);
}

static inline int getegid(void)
{
	__SYSCALL_0P(SYS_getegid);
}

static inline void* mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
	long result = __SYSCALL_6(SYS_mmap, addr, len, prot, flags, fildes, off);
	if(result < 0) {
		errno = -result;
		return MAP_FAILED;
	}
	return (void*) result;
}

static inline int munmap(void *addr, size_t len)
{
	__SYSCALL_2P(SYS_munmap, addr, len);
}

static inline int mprotect(void *addr, size_t len, int prot)
{
	__SYSCALL_3P(SYS_mprotect, addr, len, prot);
}

// syscall functions
#if 0
static inline int64_t syscall(int64_t n, ...)
{
	va_list ap;
	int64_t a, b, c, d, e, f;
	va_start(ap, n);
	a = va_arg(ap, int64_t);
	b = va_arg(ap, int64_t);
	c = va_arg(ap, int64_t);
	d = va_arg(ap, int64_t);
	e = va_arg(ap, int64_t);
	f = va_arg(ap, int64_t);
	va_end(ap);
	__SYSCALL_6P(n, a, b, c, d, e, f);
}
#endif

// pure userspace functions
static inline int strlen(const char *s)
{
	char *p = (char*) s;
	for (; *p; p++)
		;
	return p - s;
}

static inline void *memset(void *s, int c, size_t n)
{
	char *p = (char*) s;
	for(size_t i = 0; i < n; i++)
		*(p++) = (char) c;
	return s;
}

static inline void *memcpy(void *dst, const void *src, size_t n)
{
	char *d = (char*) dst;
	char *s = (char*) src;
	for(size_t i = 0; i < n; i++)
		*(d++) = *(s++);
	return dst;
}

static inline int memcmp(const void *s1, const void *s2, size_t n)
{
	char *a = (char*) s1;
	char *b = (char*) s2;
	while(n--) {
		if(*a != *b)
			return *a - *b;
		*a++;
		*b++;
	}
	return 0;
}

int puts(const char *s);
int sprintf(char *buf, const char *fmt, ...);
int printf(const char *fmt, ...);
void perror(const char *msg);

void *malloc(size_t size);
void free(void *ptr);

long random(void);

#define abort()	__abort(__FILE__, __LINE__)

static inline void __abort(const char* filename, int line)
{
	printf("abort: %s:%d\n", filename, line);
	exit(139);
}

#endif
