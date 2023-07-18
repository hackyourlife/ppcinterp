#include <stdarg.h>
#include <stdint.h>

#include "nanolibc.h"

static char* __sprinth(char* result, uint32_t x) // result must be char[9]
{
	const char* letters = "0123456789ABCDEF";
	char* p = &result[sizeof(result) - 1];
	*p = 0;
	if(x == 0) {
		*(--p) = '0';
		return p;
	}
	while(x != 0) {
		*(--p) = letters[x & 0x0F];
		x >>= 4;
	}
	return p;
}

static char* __sprintd(char* result, uint32_t x) // result must be char[11]
{
	char* p = &result[sizeof(result) - 1];
	*p = 0;
	if(x == 0) {
		*(--p) = '0';
		return p;
	}
	while(x != 0) {
		*(--p) = (x % 10) + 0x30;
		x /= 10;
	}
	return p;
}

static char* __sprinth64(char* result, uint64_t x)
{
	const char* letters = "0123456789ABCDEF";
	char* p = &result[sizeof(result) - 1];
	*p = 0;
	if(x == 0) {
		*(--p) = '0';
		return p;
	}
	while(x != 0) {
		*(--p) = letters[x & 0x0F];
		x >>= 4;
	}
	return p;
}

static char* __sprintd64(char* result, uint64_t x)
{
	char* p = &result[sizeof(result) - 1];
	*p = 0;
	if(x == 0) {
		*(--p) = '0';
		return p;
	}
	while(x != 0) {
		*(--p) = (x % 10) + 0x30;
		x /= 10;
	}
	return p;
}

int vsprintf(char* buf, const char* s, va_list args)
{
	char tmp[16];
	char* c;
	char* p = buf;
	int n;
	char pad = 0;
	int t;
	for(; *s != 0; s++) {
		if(*s == '%') {
			pad = 0;
			n = 0;
			s++;
			if(*s == '0') {
				s++;
				pad = '0';
			}
			while((*s >= '0') && (*s <= '9')) {
				n *= 10;
				n += *s - '0';
				s++;
				if(!pad)
					pad = ' ';
			}
			if(*s == 'd') {
				int val = va_arg(args, int);
				c = __sprintd(tmp, val);
				t = n - strlen(c);
				if(pad)
					for(; t > 0; t--)
						*(p++) = pad;
				for(; *c != 0; c++)
					*(p++) = *c;
			} else if(*s == 'x') {
				int val = va_arg(args, int);
				c = __sprinth(tmp, val);
				t = n - strlen(c);
				if(pad)
					for(; t > 0; t--)
						*(p++) = pad;
				for(; *c != 0; c++)
					*(p++) = *c | 0x20;
			} else if(*s == 'X') {
				int val = va_arg(args, int);
				c = __sprinth(tmp, val);
				t = n - strlen(c);
				if(pad)
					for(; t > 0; t--)
						*(p++) = pad;
				for(; *c != 0; c++)
					*(p++) = *c;
			} else if(*s == 'l') {
				s++;
				if(*s == 'd') {
					long val = va_arg(args, long);
#ifdef LONG32
					c = __sprintd(tmp, val);
#else
					c = __sprintd64(tmp, val);
#endif
					t = n - strlen(c);
					if(pad)
						for(; t > 0; t--)
							*(p++) = pad;
					for(; *c != 0; c++)
						*(p++) = *c;
				} else if(*s == 'x') {
					long val = va_arg(args, long);
#ifdef LONG32
					c = __sprinth(tmp, val);
#else
					c = __sprinth64(tmp, val);
#endif
					t = n - strlen(c);
					if(pad)
						for(; t > 0; t--)
							*(p++) = pad;
					for(; *c != 0; c++)
						*(p++) = *c | 0x20;
				} else if(*s == 'X') {
					long val = va_arg(args, long);
#ifdef LONG32
					c = __sprinth(tmp, val);
#else
					c = __sprinth64(tmp, val);
#endif
					t = n - strlen(c);
					if(pad)
						for(; t > 0; t--)
							*(p++) = pad;
					for(; *c != 0; c++)
						*(p++) = *c;
				}
			} else if(*s == 's') {
				c = (char*)va_arg(args, char*);
				t = n - strlen(c);
				if(pad)
					for(; t > 0; t--)
						*(p++) = ' ';
				for(; *c != 0; c++)
					*(p++) = *c;
			} else if(*s == 'c') {
				*(p++) = (char)va_arg(args, int);
			}
		} else
			*(p++) = *s;
	}
	*(p++) = 0;
	return p - buf - 1;
}

int sprintf(char* buf, const char* format, ...)
{
	va_list args;
	int result;
	va_start(args, format);
	result = vsprintf(buf, format, args);
	va_end(args);
	return result;
}

int printf(const char* format, ...)
{
	char buf[16 * 1024]; // 16kB
	va_list args;
	int result;
	va_start(args, format);
	result = vsprintf(buf, format, args);
	write(1, buf, result);
	va_end(args);
	return result;
}

int puts(const char* s)
{
	size_t len = strlen(s);
	size_t written = write(1, s, len);
	write(1, "\n", 1);
	return written + 1;
}

void perror(const char* msg)
{
	printf("%s: %d\n", msg, errno);
}
