--- security/audit/audit_pipe.c        2014-09-26 16:37:13.000000000 +0400
+++ security/audit/audit_pipe.c        2014-09-26 17:24:20.000000000 +0400
@@ -77,7 +77,7 @@
  */
 #define        AUDIT_PIPE_QLIMIT_DEFAULT       (128)
 #define        AUDIT_PIPE_QLIMIT_MIN           (1)
-#define        AUDIT_PIPE_QLIMIT_MAX           (1024)
+#define        AUDIT_PIPE_QLIMIT_MAX           (1048576)

 /*
  * Description of an entry in an audit_pipe.
