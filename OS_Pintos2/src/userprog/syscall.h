#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

struct file_descriptor{
  int fd;
  struct file* f_ptr;
  struct list_elem elem;
};

struct lock file_sys_lock;

void syscall_init (void);
void syscall_exit(int);

#endif /* userprog/syscall.h */
