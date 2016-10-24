#ifndef __CLSYNC_MACROS_H
#define __CLSYNC_MACROS_H

#ifdef _DEBUG
#	define DEBUGV(...) __VA_ARGS__
#else
#	define DEBUGV(...)
#endif

#ifdef PARANOID
#	define PARANOIDV(...) __VA_ARGS__
#else
#	define PARANOIDV(...)
#endif

#ifdef _GNU_SOURCE
#	ifndef likely
#		define likely(x)    __builtin_expect(!!(x), 1)
#	endif
#	ifndef unlikely
#		define unlikely(x)  __builtin_expect(!!(x), 0)
#	endif
#else
#	ifndef likely
#		define likely(x)   (x)
#	endif
#	ifndef unlikely
#		define unlikely(x) (x)
#	endif
#endif

#ifndef offsetof
#	define offsetof(a, b) __builtin_offsetof(a, b)
#endif

// clang defines "__GNUC__", but not compatible with gnuc. Fixing.
#ifdef __clang__
#	ifdef __GNUC__
#		undef __GNUC__
#	endif
#endif

#define TOSTR(a) # a
#define XTOSTR(a) TOSTR(a)

#define COLLECTDELAY_INSTANT ((unsigned int)~0)


#define MSG_SECURITY_PROBLEM(a) "Security problem: "a". Don't use this application until the bug will be fixed. Report about the problem to: "AUTHOR

#define require_strlen_le(str, limit) \
	if (strlen(str) >= limit)\
		critical("length of "TOSTR(str)" (\"%s\") >= "TOSTR(limit));\
	 
#define SAFE(code, onfail) __extension__({\
		long _SAFE_rc;\
		if ((_SAFE_rc = code)) {\
			error("Got error while "TOSTR(code));\
			onfail;\
		} \
		_SAFE_rc;\
	})

#endif
