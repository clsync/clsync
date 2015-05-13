#include <stdio.h>

int main() {
	printf("%s",

#ifdef _DEBUG_SUPPORT
		"#define _DEBUG_SUPPORT\n"
#endif
#ifdef _DEBUG_FORCE
		"#define _DEBUG_FORCE\n"
#endif
#ifdef KQUEUE_SUPPORT
		"#define KQUEUE_SUPPORT\n"
#endif
#ifdef INOTIFY_SUPPORT
		"#define INOTIFY_SUPPORT\n"
#endif
#ifdef INOTIFY_OLD
		"#define INOTIFY_OLD\n"
#endif
#ifdef FANOTIFY_SUPPORT
		"#define FANOTIFY_SUPPORT\n"
#endif
#ifdef BSM_SUPPORT
		"#define BSM_SUPPORT\n"
#endif
#ifdef GIO_SUPPORT
		"#define GIO_SUPPORT\n"
#endif
#ifdef DTRACEPIPE_SUPPORT
		"#define DTRACEPIPE_SUPPORT\n"
#endif
#ifdef BACKTRACE_SUPPORT
		"#define BACKTRACE_SUPPORT\n"
#endif
#ifdef CAPABILITIES_SUPPORT
		"#define CAPABILITIES_SUPPORT\n"
#endif
#ifdef SECCOMP_SUPPORT
		"#define SECCOMP_SUPPORT\n"
#endif
#ifdef GETMNTENT_SUPPORT
		"#define GETMNTENT_SUPPORT\n"
#endif
#ifdef UNSHARE_SUPPORT
		"#define UNSHARE_SUPPORT\n"
#endif
#ifdef PIVOTROOT_OPT_SUPPORT
		"#define PIVOTROOT_OPT_SUPPORT\n"
#endif
#ifdef CGROUP_SUPPORT
		"#define CGROUP_SUPPORT\n"
#endif
#ifdef TRE_SUPPORT
		"#define TRE_SUPPORT\n"
#endif
#ifdef THREADING_SUPPORT
		"#define THREADING_SUPPORT\n"
#endif
#ifdef HL_LOCKS
		"#define HL_LOCKS\n"
#endif
	);
	return 0;
}
