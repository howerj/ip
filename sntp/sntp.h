/*- Project:    A simple SNTP client
  - Author:     Richard James Howe
  - License:    The Unlicense
  - Email:      howe.r.j.89@gmail.com
  - Repository: https://github.com/howerj/sntp */
#ifndef SNTP_H
#define SNTP_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SNTP_API
#define SNTP_API
#endif

SNTP_API int sntp(const char *server, unsigned port, unsigned long *seconds, unsigned long *fractional);

#ifdef __cplusplus
}
#endif
#endif
