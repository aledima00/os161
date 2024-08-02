#include <execv.h>
#include <kern/fcntl.h>
#include <lib.h>
#include <current.h>
#include <kern/errno.h>
#include <copyinout.h>
#include <proc.h>
#include <syscall.h>

static int _is_userptr_valid(const userptr_t ptr, size_t size) {
    // local function that is used to check a userptr's validity
    char test;
    return copyin(ptr, &test, size) == 0; // use copyin to check validity has there is an interna validation
}

static void _execdata_nullinit(struct execdata* ed){
    // local function that just perform the NULL-initialization of pointers (and zero-init of some variables)
    // !! Note that all pointers are NULL initialized to guarantee a safe cleanup
    //    but the same operation should be done later @allocation of kargv pointers
    ed->v=NULL;
    ed->kargv=NULL;
    ed->kargc=0;
    ed->progname=NULL;
    ed->oldas=NULL;
    ed->newas=NULL;
    ed->uargv=NULL;
    ed->errnum=EXECV_NO_ERROR;
    ed->vfs_state = EXECV_VFS_CLOSED;
    ed->as_state = EXECV_OLDAS_FIXED;
}

// macro to improve readability, that returns if the provided condition (first param) is true.
// this macro should not be used directly, instead it should be redefined locally by functions with specific pointer name (execdata_ptr)
#define __CONDITIONAL_RETURN(execdata_ptr,condition,error_code){\
        if(condition){\
            if(error_code!=EXECV_ERROR_ALR_SET){\
                execdata_ptr->errnum=error_code;\
            }\
            return;\
        }\
    }

void execdata_init(struct execdata* ed, const char *pathname, char *const argv[]){
    _execdata_nullinit(ed); /* calls the local initialization function */
    
    #define INIT_CONDITIONAL_RETURN(condition,error_code) __CONDITIONAL_RETURN(ed,condition,error_code)
    // specific conditional return MACRO redefined for this function

    INIT_CONDITIONAL_RETURN(!_is_userptr_valid((userptr_t)pathname,sizeof(const char*)),EFAULT);
    INIT_CONDITIONAL_RETURN(!_is_userptr_valid((userptr_t)argv, sizeof(char*const)), EFAULT);
    for(ed->kargc = 0; argv[ed->kargc] != NULL; ed->kargc++){ // counts argc
      // meanwhile, check if argv[i] ptr is a valid user process pointer
      INIT_CONDITIONAL_RETURN(!_is_userptr_valid((userptr_t)argv[ed->kargc], sizeof(char)), EFAULT);
    }

    // ----- pathname checked, progname allocated to hold a copy of pathname
    int progname_len = strlen(pathname)+1;
    INIT_CONDITIONAL_RETURN(progname_len<=1,EINVAL);

    ed->progname = (char *)kmalloc(progname_len*sizeof(char));
    INIT_CONDITIONAL_RETURN(ed->progname==NULL,ENOMEM);

    ed->errnum = copyinstr((userptr_t)pathname, ed->progname, progname_len, NULL);
    INIT_CONDITIONAL_RETURN(ed->errnum!=0,EXECV_ERROR_ALR_SET);

    // ----- kargv allocation and NULL-initialization
    ed->kargv = (char **)kmalloc((ed->kargc + 1) * sizeof(char *));
    INIT_CONDITIONAL_RETURN(ed->kargv==NULL,ENOMEM);
    for (int i = 0; i < ed->kargc; i++){
        ed->kargv[i] = NULL; // NULL-init
    }

    // ----- kargv[i] allocation and copy: from user-side (calling process) to kernel side
    for (int i = 0; i < ed->kargc; i++) {
        size_t arglen = strlen(argv[i])+1;
        ed->kargv[i] = (char *)kmalloc(arglen*sizeof(char));
        INIT_CONDITIONAL_RETURN(arglen <=1, EINVAL);
        INIT_CONDITIONAL_RETURN(ed->kargv==NULL,ENOMEM);
        ed->errnum = copyinstr((const_userptr_t)argv[i], ed->kargv[i], arglen, NULL);
        INIT_CONDITIONAL_RETURN(ed->errnum!=0,EXECV_ERROR_ALR_SET);
    }
    ed->kargv[ed->kargc] = NULL; // NULL termination
    return;
}

void execdata_prepare(struct execdata* ed){
    #define PREPARE_CONDITIONAL_RETURN(condition,error_code) __CONDITIONAL_RETURN(ed,condition,error_code)
    // specific conditional return MACRO redefined for this function

    // ----- open the executable file
    ed->errnum = vfs_open(ed->progname, O_RDONLY, 0, &ed->v);
    PREPARE_CONDITIONAL_RETURN(ed->errnum!=0,EXECV_ERROR_ALR_SET);
    ed->vfs_state = EXECV_VFS_OPEN;

    // ----- create a new address space
    ed->newas = as_create();
    PREPARE_CONDITIONAL_RETURN(ed->newas==NULL,ENOMEM);
    ed->as_state = EXECV_NEWAS_DEFINED;

    // ----- save the old address space and switch to the new one
    ed->oldas = proc_setas(ed->newas);
    as_activate();
    ed->as_state = EXECV_NEWAS_SWITCHED;

    // ----- load the executable into the new address space
    ed->errnum = load_elf(ed->v, &ed->entrypoint);
    PREPARE_CONDITIONAL_RETURN(ed->errnum!=0,EXECV_ERROR_ALR_SET);

    // ----- done with the file now
    vfs_close(ed->v);
    ed->vfs_state = EXECV_VFS_CLOSED;

    // ----- define the user stack in the new address space
    ed->errnum = as_define_stack(ed->newas, &ed->stackptr);
    PREPARE_CONDITIONAL_RETURN(ed->errnum!=0,EXECV_ERROR_ALR_SET);

    // ----- uargv data structure allocation: holds user stack argv pointers
    ed->uargv = (vaddr_t *)kmalloc((ed->kargc + 1) * sizeof(vaddr_t));
    PREPARE_CONDITIONAL_RETURN(ed->uargv == NULL,ENOMEM);

    // ----- allocate user stack while gradually copying argv[i] data into it and saving references into uargv
    for (int i = ed->kargc - 1; i >= 0; i--) {
        size_t arglen = ROUNDUP(strlen(ed->kargv[i]) + 1, 8); // align data on stack
        // Check for potential underflow before decrementing stack pointer
        PREPARE_CONDITIONAL_RETURN(ed->stackptr < arglen, ENOMEM);
        ed->stackptr -= arglen; // allocate stack by decrementing SP
        ed->errnum = copyoutstr(ed->kargv[i], (userptr_t)ed->stackptr, arglen, NULL);
        PREPARE_CONDITIONAL_RETURN(ed->errnum!=0, EXECV_ERROR_ALR_SET);
        ed->uargv[i] = ed->stackptr; // save pointer for the user-stack version of the array
    }
    ed->uargv[ed->kargc] = (vaddr_t)NULL; // last is NULL (terminating)

    // ----- Allocate and save uargv (array of user stack argv ptrs) into the user stack
    size_t uargv_size = sizeof(vaddr_t) * (ed->kargc + 1);
    PREPARE_CONDITIONAL_RETURN(ed->stackptr < uargv_size, ENOMEM);
    ed->stackptr -= uargv_size; // allocate last stack space for uargv
    ed->errnum = copyout(ed->uargv, (userptr_t)ed->stackptr, uargv_size);
    PREPARE_CONDITIONAL_RETURN(ed->errnum!=0, EXECV_ERROR_ALR_SET);
}

void execdata_switch(struct execdata* ed){

    // ----- set NEWAS as fixed (definitively)
    ed->as_state = EXECV_NEWAS_FIXED;
    
    // ----- program name substituted
    if(curthread->t_name!=NULL){
        kfree(curthread->t_name);
    }
    curthread->t_name = kstrdup(ed->progname);
    if(curthread->t_name==NULL){
        ed->errnum = ENOMEM;
        return;
    }

    // ----- cleans up unnecessary data without destroying the whole structure
    execdata_cleanup(ed);

    // ----- enter user mode and start executing the new process image
    enter_new_process(ed->kargc, (userptr_t)ed->stackptr, NULL, ed->stackptr, ed->entrypoint);

    // ------ should never reach this point ------
    panic("enter_new_process returned\n");
    ed->errnum=EINVAL;
    return; // Should never reach here
}

void execdata_cleanup(struct execdata* ed){
    // local function that perform a conditional cleanup:
    // - to_be_destroyed = 0 -> does not free the ptr of the data structure, just clean up unnecessary data
    // - to_be_destroyed = 1 -> also destroys the data structure by freeing its pointer

    // !! Note that externally it is only allowed to call a mandatory-destroying wrapper version,
    //    as the non-destroying version is only invoked internally in case of successful execv

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
    if(ed->vfs_state==EXECV_VFS_OPEN){
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
