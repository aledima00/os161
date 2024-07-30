/*
 * AUthor: G.Cabodi
 * Very simple implementation of sys__exit.
 * It just avoids crash/panic. Full process exit still TODO
 * Address space is released
 */

#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
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
#include <kern/wait.h>
#include <kern/fcntl.h>
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
  spinlock_acquire(&p->p_lock);
  p->p_terminated=1; //The process is terminated
  spinlock_release(&p->p_lock);
  proc_remthread(curthread);
  proc_signal_end(p); //It signals the end of a process, does not destroy the proc
#else
  /* get address space of current process and destroy */
  struct addrspace *as = proc_getas();
  as_destroy(as);
#endif
  thread_exit();
  panic("thread_exit returned (should not happen)\n");
}

int sys_waitpid(pid_t pid, userptr_t statusp, int options, int *err) {
#if OPT_C2
    /*pid can be >0, -1 or <-1. The latter case is not considered because it references the group id (not handled)
      pid = -1 should wait for any of its child 
      this means that the pid is constrained to be >0*/

    if (pid <= 0) { 
        *err=ENOSYS;
        return -1;
    }
    /*ECHILD is returned if the process hasn't got any unwaiting children*/
    if(curproc->p_children_list==NULL){
      *err = ECHILD;
      return -1;
    }
    /*Check that statusp is valid to pass badcall tests*/
    if(statusp!=NULL){
      int result;
      int dummy;
      result = copyin((const_userptr_t)statusp, &dummy, sizeof(dummy)); //It's easy to do it through copyin
      if (result) {
          *err = EFAULT;
          return -1;
      }
    }
  
    /*The process is allowed to wait only for a process that is its child*/
    int ret = check_is_child(pid);
    /*The process doesn't exist*/
    if (ret == -1) { 
      *err = ESRCH;
      return -1;
    }
    /*The process is not a child of the calling process*/
    if (ret == 0) { 
      *err = ECHILD;
      return -1;
    }

    struct proc *p = proc_search_pid(pid);
    
    switch (options) {
      case 0:
        // No options, standard blocking wait
        break;
      case WNOHANG:{
        /*Check if any of the children of the calling process has terminated. In this case, return its pid and status, otherwise 0*/
        struct proc *p= check_is_terminated(curproc);
        if (p == NULL) {
            return 0;
        }
        /*Otherwise it goes on with p, it performs the wait which is non-blocking, frees the list by the child and destroys the proc data structure*/
        break;}
      /*case WEXITED: { It's not standard
        // Check if the child process has exited
        if (p->p_terminated==1) {
          break; // Exit normally if child has exited
        }
        *err = ECHILD;
        return -1;
      }*/
      default:{
        *err=EINVAL; 
        return -1;
      }
    }

    int s = proc_wait(p);
    if (statusp != NULL) {
        // Use a temporary variable to ensure alignment
        int kstatus;
        kstatus = s;
        // Copy the status back to user space
        int result = copyout(&kstatus, statusp, sizeof(kstatus));
        if (result) {
            *err = EFAULT;
            return -1;
        }
    }

    return pid;
#endif
}

pid_t
sys_getpid(void)
{
  #if OPT_C2
    KASSERT(curproc != NULL);
    return curproc->p_pid;
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
  /*It's not acceptable that it crashes if there are already too many processes, It has to return the correct error*/
  KASSERT(curproc != NULL);
  if(proc_verify_pid()==-1){ 
    return ENPROC; 
  }
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

  /* Parent and child linked so that children terminate on parent exit */
  
  struct child_node *newChild = kmalloc(sizeof(struct child_node));
  if(newChild == NULL){
    return ENOMEM;
  }
  //Chil added to the children list of the father
  newChild->p = newp;
  newChild->next = curproc->p_children_list;
  curproc->p_children_list = newChild;
  //Father added to the father list of the children (to remove it later)
  newp->p_father_proc = curproc;
  
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

#endif

#if OPT_C2

/* c2 - Alessandro Di Matteo [START] */
/* internal implementation of the syscall sys_execv(...). */

static int is_user_pointer_valid(const userptr_t ptr, size_t size) {
    char test;
    return copyin(ptr, &test, size) == 0;
}

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
    
    // Check if argv ptr is a valid user process pointer
    _EXECV_HANDLE_ERROR(!is_user_pointer_valid((userptr_t)argv,sizeof(char*const)),EFAULT,false,false);

    // Count the number of arguments and check their validity
    for(argc = 0; argv[argc] != NULL; argc++){
      // Check if argv[i] ptr is a valid user process pointer
      _EXECV_HANDLE_ERROR(!is_user_pointer_valid((userptr_t)argv[argc],sizeof(char)),EFAULT,false,false);
    }

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

