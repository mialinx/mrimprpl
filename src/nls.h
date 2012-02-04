#ifndef NLS_H
#define NLS_H

#ifdef ENABLE_NLS
    #include <libintl.h>
    #define __(a) (dgettext(PACKAGE, (a)))
#else
    #define __(a) (a)
#endif

#endif
