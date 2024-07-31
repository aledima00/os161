#ifndef _EXECV_H_
#define _EXECV_H_

#include <types.h>
#include <vfs.h>
#include <addrspace.h>
#include <errno.h>
#include "opt-c2.h"

#if OPT_C2

#define EXECV_NO_ERROR 0
#define EXECV_ERROR_ALR_SET -1

typedef enum execv_vfs_state_t{
    EXECV_VFS_OPEN,
    EXECV_VFS_CLOSED
} execv_vfs_state_t;

typedef enum execv_as_state_t{
    EXECV_OLDAS_FIXED,
    EXECV_NEWAS_DEFINED,
    EXECV_NEWAS_SWITCHED,
    EXECV_NEWAS_FIXED
} execv_as_state_t;

struct execdata{
    struct vnode *v; // abstract executable file
    vaddr_t entrypoint;
    vaddr_t stackptr;
    char** kargv;
    int kargc;
    char* progname;
    int progname_len;
    struct addrspace *oldas;
    struct addrspace *newas;
    vaddr_t *uargv;

    int errnum; // 0 = no error

    execv_vfs_state_t vfs_state;
    execv_as_state_t as_state;
};

struct execdata* execdata_init(const char *pathname, char *const argv[]);
void execdata_prepare(struct execdata* ed);
void execdata_switch(struct execdata* ed);

void execdata_cleanup(struct execdata* ed);


#endif

#endif /* _EXECV_H_ */