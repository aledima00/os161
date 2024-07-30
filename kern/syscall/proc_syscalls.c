/*
 * AUthor: G.Cabodi
 * Very simple implementation of sys__exit.
 * It just avoids crash/panic. Full process exit still TODO
 * Address space is released
 */

#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <kern/fcntl.h>
#include <clock.h>
#include <copyinout.h>
#include <syscall.h>
#include <lib.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <mips/trapframe.h>
#include <current.h>
#include <synch.h>
#include <vfs.h>

/*
 * system calls for process management
 */
void
sys__exit(int status)
{
#if OPT_C2
  struct proc *p = curproc;
  p->p_status = status & 0xff; /* just lower 8 bits returned */
  proc_remthread(curthread);
  proc_signal_end(p);
#else
  /* get address space of current process and destroy */
  struct addrspace *as = proc_getas();
  as_destroy(as);
#endif
  thread_exit();

  panic("thread_exit returned (should not happen)\n");
  (void) status; // TODO: status handling
}

int
sys_waitpid(pid_t pid, userptr_t statusp, int options)
{
#if OPT_C2
  struct proc *p = proc_search_pid(pid);
  int s;
  (void)options; /* not handled */
  if (p==NULL) return -1;
  s = proc_wait(p);
  if (statusp!=NULL) 
    *(int*)statusp = s;
  return pid;
#else
  (void)options; /* not handled */
  (void)pid;
  (void)statusp;
  return -1;
#endif
}

pid_t
sys_getpid(void)
{
#if OPT_C2
  KASSERT(curproc != NULL);
  return curproc->p_pid;
#else
  return -1;
#endif
}

#if OPT_C2
static void
call_enter_forked_process(void *tfv, unsigned long dummy) {
  struct trapframe *tf = (struct trapframe *)tfv;
  (void)dummy;
  enter_forked_process(tf); 
 
  panic("enter_forked_process returned (should not happen)\n");
}

int sys_fork(struct trapframe *ctf, pid_t *retval) {
  struct trapframe *tf_child;
  struct proc *newp;
  int result;

  KASSERT(curproc != NULL);

  newp = proc_create_runprogram(curproc->p_name);
  if (newp == NULL) {
    return ENOMEM;
  }

  /* done here as we need to duplicate the address space 
     of thbe current process */
  as_copy(curproc->p_addrspace, &(newp->p_addrspace));
  if(newp->p_addrspace == NULL){
    proc_destroy(newp); 
    return ENOMEM; 
  }

  proc_file_table_copy(newp,curproc);

  /* we need a copy of the parent's trapframe */
  tf_child = kmalloc(sizeof(struct trapframe));
  if(tf_child == NULL){
    proc_destroy(newp);
    return ENOMEM; 
  }
  memcpy(tf_child, ctf, sizeof(struct trapframe));

  /* TO BE DONE: linking parent/child, so that child terminated 
     on parent exit */

  result = thread_fork(
		 curthread->t_name, newp,
		 call_enter_forked_process, 
		 (void *)tf_child, (unsigned long)0/*unused*/);

  if (result){
    proc_destroy(newp);
    kfree(tf_child);
    return ENOMEM;
  }

  *retval = newp->p_pid;

  return 0;
}

/* c2 - Alessandro Di Matteo [START] */
/* internal implementation of the syscall sys_execv(...). */

// Function to replace the current process image with a new one
int sys_execv(const char *pathname, char *const argv[]){

    struct vnode *v=NULL;
    vaddr_t entrypoint, stackptr;
    int result;
    size_t actual;
    char **kargs=NULL;
    int argc, i;
    char *progname=NULL; // new program name
    struct addrspace *oldas=NULL; // current address space (before execv)
    struct addrspace *newas=NULL; // next address space (after execv)
    vaddr_t *arg_ptrs=(vaddr_t*)NULL;
    
    #define _EXECV_CLEANUP(){\
      if(progname!=NULL){\
        kfree(progname);\
        progname=NULL;\
      }\
      if(kargs!=NULL){\
        for(int j=0;j<argc && kargs[j]!=NULL;j++){\
          kfree(kargs[j]);\
          kargs[j]=NULL;\
        }\
        kfree(kargs);\
        kargs=NULL;\
      }\
      if(arg_ptrs!=NULL){\
        kfree(arg_ptrs);\
        arg_ptrs=NULL;\
      }\
    }

    #define _EXECV_HANDLE_ERROR(is_error,error,close_vfs,restore_oldas){\
      if(is_error){\
        _EXECV_CLEANUP();\
        if(close_vfs){\
          vfs_close(v);\
        }\
        if(restore_oldas){\
          proc_setas(oldas);\
          as_activate();\
          as_destroy(newas);\
        }\
        return error;\
      }\
    }

    
    

    KASSERT(curproc!=NULL); // WRNING
    _EXECV_HANDLE_ERROR(pathname == NULL,EFAULT,false,false); // NULL parameter

    // Allocate kernel buffer for the program pathname
    progname = (char *)kmalloc(PATH_MAX*sizeof(char));
    _EXECV_HANDLE_ERROR(progname == NULL,ENOMEM,false,false);
    
    // Copy the program pathname from user space to kernel space
    result = copyinstr((userptr_t)pathname, progname, PATH_MAX, &actual);
    _EXECV_HANDLE_ERROR(result,result,false,false);
    _EXECV_HANDLE_ERROR(strlen(progname)==0,EINVAL,false,false); // invalid (empty) parameter
    
    // Check if argv is NULL
    _EXECV_HANDLE_ERROR(argv==NULL,EFAULT,false,false);

    // Count the number of arguments
    for(argc = 0; argv[argc] != NULL; argc++);

    // Allocate space for arguments in kernel space
    kargs = (char **)kmalloc((argc + 1) * sizeof(char *));
    _EXECV_HANDLE_ERROR(kargs==NULL,ENOMEM,false,false);

    // Copy each argument from user space to kernel space
    for (i = 0; i < argc; i++) {
        kargs[i] = (char *)kmalloc(ARG_MAX);
        _EXECV_HANDLE_ERROR(kargs[i] == NULL,ENOMEM,false,false);
        result = copyinstr((const_userptr_t)argv[i], kargs[i], ARG_MAX, &actual);
        _EXECV_HANDLE_ERROR(result,result,false,false);
    }
    kargs[argc] = NULL;

    // Open the executable file
    result = vfs_open(progname, O_RDONLY, 0, &v);
    _EXECV_HANDLE_ERROR(result,result,false,false);

    // Create a new address space
    newas = as_create();
    _EXECV_HANDLE_ERROR(newas==NULL,ENOMEM,true,false);

    // Save the old address space and switch to the new one
    oldas = proc_setas(newas);
    as_activate();

    // Load the executable into the new address space
    result = load_elf(v, &entrypoint);

    // Done with the file now
    vfs_close(v);

    // Define the user stack in the new address space
    result = as_define_stack(newas, &stackptr);
    _EXECV_HANDLE_ERROR(result,result,false,true);

    // {argv} Allocate space for arguments vector in kernel space
    arg_ptrs = (vaddr_t *)kmalloc((argc + 1) * sizeof(vaddr_t));
    _EXECV_HANDLE_ERROR(arg_ptrs == NULL,ENOMEM,false,true);

    // {argv[i]} Allocate kernel space while gradually copying data into it and saving references
    for (i = argc - 1; i >= 0; i--) {
        size_t arglen = ROUNDUP(strlen(kargs[i]) + 1, 8);
        stackptr -= arglen;
        result = copyoutstr(kargs[i], (userptr_t)stackptr, arglen, NULL);
        _EXECV_HANDLE_ERROR(result,result,false,true);
        arg_ptrs[i] = stackptr; // save pointer for the user-stack version of the array
    }
    arg_ptrs[argc] = (vaddr_t)NULL; // last is NULL (terminating)

    // Allocate and save the vector of references into the stack (argv)
    stackptr -= sizeof(vaddr_t) * (argc + 1);
    result = copyout(arg_ptrs, (userptr_t)stackptr, sizeof(vaddr_t) * (argc + 1));
    _EXECV_HANDLE_ERROR(result,result,false,true);

    // Clean up kernel allocated data
    kfree(curthread->t_name);
    curthread->t_name = progname;
    progname=NULL; // move the reference -> not deleted by _EXECV_CLEANUP
    _EXECV_CLEANUP();
    as_destroy(oldas);

    // Enter user mode and start executing the new process image
    enter_new_process(argc, (userptr_t)stackptr, NULL, stackptr, entrypoint);

    // enter_new_process does not return if successful
    panic("enter_new_process returned\n");
    return EINVAL; // Should never reach here
}

/* c2 - Alessandro Di Matteo [END] */

#endif