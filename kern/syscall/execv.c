#include <execv.h>
#include "string.h"
#include <kern/fcntl.h>
#include <lib.h>
#include <current.h>

static int is_userptr_valid(const userptr_t ptr, size_t size) {
    char test;
    return copyin(ptr, &test, size) == 0;
}

struct execdata* _create_execdata(void){
    struct execdata* ret = (struct execdata*)kmalloc(sizeof(struct execdata));
    if(ret==NULL)
        return ret;
    ret->v=NULL;
    ret->kargv=NULL;
    ret->kargc=0;
    ret->progname=NULL;
    ret->progname_len=0;
    ret->oldas=NULL;
    ret->newas=NULL;
    ret->uargv=NULL;
    ret->errnum=EXECV_NO_ERROR;
    ret->vfs_state = EXECV_VFS_CLOSED;
    ret->as_state = EXECV_OLDAS_FIXED;
    return ret;
}

#define __CONDITIONAL_RETURN(execdata_ptr,condition,error_code,retval){\
        if(condition){\
            if(execdata_ptr->errnum!=EXECV_ERROR_ALR_SET){\
                execdata_ptr->errnum=error_code;\
            }\
            return retval;\
        }\
    }

struct execdata* execdata_init(const char *pathname, char *const argv[]){
    struct execdata* ret = _create_execdata();
    if(ret==NULL)
        return ret;
    
    #define INIT_CONDITIONAL_RETURN(condition,error_code) __CONDITIONAL_RETURN(ret,condition,error_code,ret)

    INIT_CONDITIONAL_RETURN(!is_userptr_valid((userptr_t)pathname,sizeof(const char*)),EINVAL);
    INIT_CONDITIONAL_RETURN(!is_userptr_valid((userptr_t)argv, sizeof(char*const)), EINVAL);
    for(ret->kargc = 0; argv[ret->kargc] != NULL; ret->kargc++){
      // Check if argv[i] ptr is a valid user process pointer
      INIT_CONDITIONAL_RETURN(!is_userptr_valid((userptr_t)argv[ret->kargc], sizeof(char)), EINVAL);
    }

    INIT_CONDITIONAL_RETURN(!is_userptr_valid((userptr_t)argv, sizeof(char*const)), EINVAL);

    ret->progname_len = strlen(pathname)+1;
    INIT_CONDITIONAL_RETURN(ret->progname_len==0,EINVAL);

    ret->progname = (char *)kmalloc(ret->progname_len*sizeof(char));
    INIT_CONDITIONAL_RETURN(ret->progname==NULL,ENOMEM);

    ret->errnum = copyinstr((userptr_t)pathname, ret->progname, ret->progname_len, NULL);
    INIT_CONDITIONAL_RETURN(ret->errnum!=0,EXECV_ERROR_ALR_SET);

    ret->kargv = (char **)kmalloc((ret->kargc + 1) * sizeof(char *));
    INIT_CONDITIONAL_RETURN(ret->kargv==NULL,ENOMEM);

    // Copy each argument from user space to kernel space
    for (int i = 0; i < ret->kargc; i++) {
        unsigned int arglen = strlen(ret->kargv[i])+1;
        ret->kargv[i] = (char *)kmalloc(arglen*sizeof(char));
        INIT_CONDITIONAL_RETURN(ret->kargv==NULL,ENOMEM);
        ret->errnum = copyinstr((const_userptr_t)argv[i], ret->kargv[i], arglen, NULL);
        INIT_CONDITIONAL_RETURN(ret->errnum!=0,EXECV_ERROR_ALR_SET);
    }
    ret->kargv[ret->kargc] = NULL;
}

void execdata_prepare(struct execdata* ed){
    #define PREPARE_CONDITIONAL_RETURN(condition,error_code) __CONDITIONAL_RETURN(ed,condition,error_code,)
    // Open the executable file
    ed->errnum = vfs_open(ed->progname, O_RDONLY, 0, &ed->v);
    PREPARE_CONDITIONAL_RETURN(ed->errnum!=0,EXECV_ERROR_ALR_SET);
    ed->vfs_state = EXECV_VFS_OPEN;

    // Create a new address space
    ed->newas = as_create();
    PREPARE_CONDITIONAL_RETURN(ed->newas==NULL,ENOMEM);
    ed->as_state = EXECV_NEWAS_DEFINED;

    // Save the old address space and switch to the new one
    ed->oldas = proc_setas(ed->newas);
    as_activate();
    ed->as_state = EXECV_NEWAS_SWITCHED;

    // Load the executable into the new address space
    ed->errnum = load_elf(ed->v, &ed->entrypoint);
    PREPARE_CONDITIONAL_RETURN(ed->errnum!=0,EXECV_ERROR_ALR_SET);

    // Done with the file now
    vfs_close(ed->v);
    ed->vfs_state = EXECV_VFS_CLOSED;

    // Define the user stack in the new address space
    ed->errnum = as_define_stack(ed->newas, &ed->stackptr);
    PREPARE_CONDITIONAL_RETURN(ed->errnum!=0,EXECV_ERROR_ALR_SET);

    // user-argv allocation
    ed->uargv = (vaddr_t *)kmalloc((ed->kargc + 1) * sizeof(vaddr_t));
    PREPARE_CONDITIONAL_RETURN(ed->uargv == NULL,ENOMEM);

    // {argv[i]} Allocate user space while gradually copying data into it and saving references into uargv
    for (unsigned int i = ed->kargc - 1; i >= 0; i--) {
        size_t arglen = ROUNDUP(strlen(ed->kargv[i]) + 1, 8); // align data on stack
        ed->stackptr -= arglen; // allocate stack
        ed->errnum = copyoutstr(ed->kargv[i], (userptr_t)ed->stackptr, arglen, NULL);
        PREPARE_CONDITIONAL_RETURN(ed->errnum!=0, EXECV_ERROR_ALR_SET);
        ed->uargv[i] = ed->stackptr; // save pointer for the user-stack version of the array
    }
    ed->uargv[ed->kargc] = (vaddr_t)NULL; // last is NULL (terminating)

    // Allocate and save the vector of references into the stack (argv)
    ed->stackptr -= sizeof(vaddr_t) * (ed->kargc + 1); // allocate last stack space for uargv
    ed->errnum = copyout(ed->uargv, (userptr_t)ed->stackptr, sizeof(vaddr_t) * (ed->kargc + 1));
    PREPARE_CONDITIONAL_RETURN(ed->errnum!=0, EXECV_ERROR_ALR_SET);
}

void execdata_switch(struct execdata* ed){
    // Clean up kernel allocated data
    kfree(curthread->t_name);
    curthread->t_name = ed->progname;
    ed->progname=NULL; // move the reference -> not deleted by cleanup
    execdata_cleanup(ed);

    // Enter user mode and start executing the new process image
    enter_new_process(ed->kargc, (userptr_t)ed->stackptr, NULL, ed->stackptr, ed->entrypoint);

    // enter_new_process does not return if successful
    panic("enter_new_process returned\n");
    return EINVAL; // Should never reach here
}

void execdata_cleanup(struct execdata* ed){
    if(ed->progname!=NULL){
        kfree(ed->progname);
        ed->progname=NULL;
    }
    if(ed->kargv!=NULL){
        for(int j=0;j<ed->kargc && ed->kargv[j]!=NULL;j++){
            kfree(ed->kargv[j]);
            ed->kargv[j]=NULL;
        }
        kfree(ed->kargv);
        ed->kargv=NULL;
    }
    if(ed->uargv!=NULL){
        kfree(ed->uargv);
        ed->uargv=NULL;
    }
    if(ed->vfs_state==EXECV_VFS_CLOSED){
        vfs_close(ed->v);
    }
    if(ed->as_state==EXECV_NEWAS_FIXED){
        as_destroy(ed->oldas);
    }
    else if(ed->as_state==EXECV_NEWAS_SWITCHED){
        proc_setas(ed->oldas);
        as_activate();
        as_destroy(ed->newas);
    }
    else if(ed->as_state==EXECV_NEWAS_DEFINED){
        as_destroy(ed->newas);
    }
}
