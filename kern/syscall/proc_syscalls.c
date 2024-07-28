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
    struct vnode *v;
    vaddr_t entrypoint, stackptr;
    int result;
    size_t actual;
    char **kargs;
    int argc, i;
    char *progname; // new program name
    struct addrspace *oldas; // current address space (before execv)
    struct addrspace *newas; // next address space (after execv)

    KASSERT(curproc!=NULL);

    if (pathname == NULL) {
        return EFAULT;
    }

    // Allocate kernel buffer for the program pathname
    progname = (char *)kmalloc(PATH_MAX*sizeof(char));
    if (progname == NULL) {
        return ENOMEM;
    }
    // Copy the program pathname from user space to kernel space
    result = copyinstr((userptr_t)pathname, progname, PATH_MAX, &actual);
    if (result) {
      kfree(progname);
      return result;
    }

    // Check if argv is NULL
    if (argv == NULL) {
      kfree(progname);
      return EFAULT;
    }

    // Count the number of arguments
    for(argc = 0; argv[argc] != NULL; argc++);

    // Allocate space for arguments in kernel space
    kargs = (char **)kmalloc((argc + 1) * sizeof(char *));
    if (kargs == NULL) {
        kfree(progname);
        return ENOMEM;
    }

    // check if there are NULL arguments
    for(i=0;i<argc;i++){
      if (argv[i] == NULL) {
        kfree(progname);
        kfree(kargs);
        return EFAULT;
      }
    }

    // Copy each argument from user space to kernel space
    for (i = 0; i < argc; i++) {
        kargs[i] = (char *)kmalloc(ARG_MAX);
        if (kargs[i] == NULL) {
            for (int j = 0; j < i; j++) {
                kfree(kargs[j]);
            }
            kfree(kargs);
            kfree(progname);
            return ENOMEM;
        }
        result = copyinstr((const_userptr_t)argv[i], kargs[i], ARG_MAX, &actual);
        if (result) {
            for (int j = 0; j <= i; j++) {
                kfree(kargs[j]);
            }
            kfree(kargs);
            kfree(progname);
            return result;
        }
    }
    kargs[argc] = NULL;

    // Open the executable file
    result = vfs_open(progname, O_RDONLY, 0, &v);
    if (result) {
        for (i = 0; i < argc; i++) {
            kfree(kargs[i]);
        }
        kfree(kargs);
        kfree(progname);
        return result;
    }

    // Create a new address space
    newas = as_create();
    if (newas == NULL) {
        vfs_close(v);
        for (i = 0; i < argc; i++) {
            kfree(kargs[i]);
        }
        kfree(kargs);
        kfree(progname);
        return ENOMEM;
    }

    // Save the old address space and switch to the new one
    oldas = proc_setas(newas);
    as_activate();

    // Load the executable into the new address space
    result = load_elf(v, &entrypoint);
    if (result) {
        proc_setas(oldas);
        as_activate();
        as_destroy(newas);
        vfs_close(v);
        for (i = 0; i < argc; i++) {
            kfree(kargs[i]);
        }
        kfree(kargs);
        kfree(progname);
        return result;
    }

    // Done with the file now
    vfs_close(v);

    // Define the user stack in the new address space
    result = as_define_stack(newas, &stackptr);
    if (result) {
        proc_setas(oldas);
        as_activate();
        as_destroy(newas);
        for (i = 0; i < argc; i++) {
            kfree(kargs[i]);
        }
        kfree(kargs);
        kfree(progname);
        return result;
    }

    // Copy arguments to the new stack in the user space
    vaddr_t *arg_ptrs = (vaddr_t *)kmalloc((argc + 1) * sizeof(vaddr_t));
    if (arg_ptrs == NULL) {
        proc_setas(oldas);
        as_activate();
        as_destroy(newas);
        for (i = 0; i < argc; i++) {
            kfree(kargs[i]);
        }
        kfree(kargs);
        kfree(progname);
        return ENOMEM;
    }

    // Copy arguments onto the user stack
    for (i = argc - 1; i >= 0; i--) {
        size_t arglen = ROUNDUP(strlen(kargs[i]) + 1, 8);
        stackptr -= arglen;
        result = copyoutstr(kargs[i], (userptr_t)stackptr, arglen, NULL);
        if (result) {
            proc_setas(oldas);
            as_activate();
            as_destroy(newas);
            for (i = 0; i < argc; i++) {
                kfree(kargs[i]);
            }
            kfree(kargs);
            kfree(arg_ptrs);
            kfree(progname);
            return result;
        }
        arg_ptrs[i] = stackptr;
    }
    arg_ptrs[argc] = 0;

    // Copy the array of argument pointers to the user stack
    stackptr -= sizeof(vaddr_t) * (argc + 1);
    result = copyout(arg_ptrs, (userptr_t)stackptr, sizeof(vaddr_t) * (argc + 1));
    if (result) {
        proc_setas(oldas);
        as_activate();
        as_destroy(newas);
        for (i = 0; i < argc; i++) {
            kfree(kargs[i]);
        }
        kfree(kargs);
        kfree(arg_ptrs);
        kfree(progname);
        return result;
    }

    // Clean up kernel arguments
    for (i = 0; i < argc; i++) {
        kfree(kargs[i]);
    }
    kfree(kargs);
    kfree(arg_ptrs);
    kfree(progname);

    // Enter user mode and start executing the new process image
    enter_new_process(argc, (userptr_t)(stackptr + sizeof(vaddr_t)), NULL, stackptr, entrypoint);

    // enter_new_process does not return if successful
    panic("enter_new_process returned\n");
    return EINVAL; // Should never reach here
}

/* c2 - Alessandro Di Matteo [END] */

#endif