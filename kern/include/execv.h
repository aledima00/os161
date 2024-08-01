#ifndef _EXECV_H_
#define _EXECV_H_

#include <types.h>
#include <vfs.h>
#include <addrspace.h>
#include "opt-c2.h"

#if OPT_C2

#define EXECV_NO_ERROR 0
#define EXECV_ERROR_ALR_SET -1
// does not modify the .errnum field

typedef enum execv_vfs_state_t{ // state of the vnode
    EXECV_VFS_OPEN, // Vnode should be closed when cleaning up
    EXECV_VFS_CLOSED // Vnode is already closed
} execv_vfs_state_t;

typedef enum execv_as_state_t{
    EXECV_OLDAS_FIXED, 
    EXECV_NEWAS_DEFINED, // newas to be destroyed when cleaning up
    EXECV_NEWAS_SWITCHED, // oldas to be replaced & newas to be destroyed when cleaning up
    EXECV_NEWAS_FIXED // oldas to be destroyed when cleaning up
} execv_as_state_t;

struct execdata{
    struct vnode *v; // virtual node used to read the executable file
    vaddr_t entrypoint; // virtual address where the execution of the new program should start
    vaddr_t stackptr; // virtual address of the stack pointer for the new process
    char** kargv; // kernel ptr to be allocated to hold a copy of the argv provided by the calling user process
    int kargc; // keep trace of argc in kernel side
    char* progname; // kernel string to be allocated to hold a copy of the program (path)name to be executed provided by the calling user process
    struct addrspace *oldas; // ptr to old (current) address space before being replaced, maintained for restoring purposes
    struct addrspace *newas; // ptr to new address space, that is going to replace the old one
    vaddr_t *uargv; // user-side argv for the new process

    int errnum; // maintain eventual error codes (0 = no error)

    execv_vfs_state_t vfs_state; // state of the vnode
    execv_as_state_t as_state; // state of the address spaces
};

/**
 * Create and initialize the execdata from the given parameters.
 * @return `NULL` if out of memory (no allocation), or a pointer to the allocated structure otherwise (still need to check for errors in the `.errnum` field)
 */
struct execdata* execdata_init(const char *pathname, char *const argv[]);

/**
 * Creates the new AS and loads it with the executable; it also defines the stack and fills it with arguments. Check `.errnum` field for errors.
 */
void execdata_prepare(struct execdata* ed);

/**
 * Tries to switch to the new process to be executed. Should never return.
 */
void execdata_switch(struct execdata* ed);

/**
 * Cleans up the structure, and then destroys it.
 */
void execdata_cleanup(struct execdata* ed);


#endif

#endif /* _EXECV_H_ */