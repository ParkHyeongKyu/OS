#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/syscall-nr.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "devices/shutdown.h"

// pj2

static void syscall_handler (struct intr_frame *);
void syscall_halt(void);
tid_t syscall_exec(const char *cmd_line);
int syscall_wait (tid_t pid);
bool syscall_create(const char *file, unsigned initial_size);
bool syscall_remove(const char *file);
int syscall_open(const char *file);
int syscall_filesize(int fd);
int syscall_read(int fd, void *buffer, unsigned size);
int syscall_write(int fd, const void *buffer, unsigned size);
void syscall_seek (int fd, unsigned position);
unsigned syscall_tell (int fd);
void syscall_close (int fd);
struct file* find_file_ptr(struct thread *cur, int fd);
void check_four_byte(const void* vaddr);
void is_valid_vaddr(const void* vaddr);
void check_buffer(const void* buffer, unsigned size);

static int file_count;

void
syscall_init (void) 
{
  file_count = 2;
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_sys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  is_valid_vaddr(f->esp);
  switch ((int)*(uint32_t *)f->esp){
    case SYS_HALT:
      syscall_halt();
      break;
    case SYS_EXIT:
      is_valid_vaddr(f->esp+4);
      syscall_exit((int)*(uint32_t *)(f->esp+4));
      break;
    case SYS_EXEC:
      is_valid_vaddr(f->esp+4);
      f->eax = syscall_exec((char *)*(uint32_t *)(f->esp+4));
      break;
    case SYS_WAIT:
      is_valid_vaddr(f->esp+4);
      f->eax = syscall_wait((tid_t)*(uint32_t *)(f->esp+4));
      break;
    case SYS_CREATE:
      is_valid_vaddr(f->esp+4);
      is_valid_vaddr(f->esp+8);
      f->eax = syscall_create((char *)*(uint32_t *)(f->esp+4), (unsigned)*(uint32_t *)(f->esp+8));
      break;
    case SYS_REMOVE:
      is_valid_vaddr(f->esp+4);
      f->eax = syscall_remove((char *)*(uint32_t *)(f->esp+4));
      break;
    case SYS_OPEN:
      is_valid_vaddr(f->esp+4);
      f->eax = syscall_open((char *)*(uint32_t *)(f->esp+4));
      break;
    case SYS_FILESIZE:
      is_valid_vaddr(f->esp+4);
      f->eax = syscall_filesize((int)*(uint32_t *)(f->esp+4));
      break;
    case SYS_READ:
      is_valid_vaddr(f->esp+4);
      is_valid_vaddr(f->esp+8);
      is_valid_vaddr(f->esp+12);
      f->eax = syscall_read((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp+8), (unsigned)*(uint32_t *)(f->esp+12));
      break;
    case SYS_WRITE:
      is_valid_vaddr(f->esp+4);
      is_valid_vaddr(f->esp+8);
      is_valid_vaddr(f->esp+12);
      f->eax = syscall_write((int)*(uint32_t *)(f->esp+4), (const void *)*(uint32_t *)(f->esp+8), (unsigned)*(uint32_t *)(f->esp+12));
      break;
    case SYS_SEEK:
      is_valid_vaddr(f->esp+4);
      is_valid_vaddr(f->esp+8);
      syscall_seek((int)*(uint32_t *)(f->esp+4), (unsigned)*(uint32_t *)(f->esp+8));
      break;
    case SYS_TELL:
      is_valid_vaddr(f->esp+4);
      f->eax = syscall_tell((int)*(uint32_t *)(f->esp+4));
      break;
    case SYS_CLOSE:
      is_valid_vaddr(f->esp+4);
      syscall_close((int)*(uint32_t *)(f->esp+4));
      break;
  }
  // thread_exit ();
}

void syscall_halt(void){
  // Terminates Pintos by calling shutdown_power_off()
  shutdown_power_off();
  return;
}

void syscall_exit(int status){
  // Terminates the current user program and return status to the kernel. Ther kernel passes the status to the parent process.
  struct list_elem *e;
  struct list_elem *next;
  struct file_descriptor* temp;
  struct thread *cur = thread_current();

  // 파일닫기
  lock_acquire(&file_sys_lock);
  for(e=list_begin(&cur->fd_list); e!=list_end(&cur->fd_list); e=next){
    next = list_next(e);
    temp = list_entry(e, struct file_descriptor, elem);
    list_remove(&temp->elem);
    file_close(temp->f_ptr);
    free(temp);
  }
  lock_release(&file_sys_lock);

  printf("%s: exit(%d)\n", cur->name, status);
  cur->exit_status = status;
  file_close(cur->exe_file);
  thread_exit();
  return;
}

tid_t syscall_exec(const char *cmd_line){
  // Runs the program whose name is given in cmd_line and returns the new process’s pid.
  // If its fails to execute the new program, it should return -1 as pid. Synchronization should be ensured for this system call.
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct list_elem *next;
  struct thread *child = NULL;
  bool find = false;
  tid_t pid;

  is_valid_vaddr(cmd_line);
  pid = process_execute(cmd_line);

  // 자식찾고
  for(e = list_begin(&cur->child_list); e != list_end(&(cur->child_list)); e = next){
    next = list_next(e);
    child = list_entry(e, struct thread, child_elem);
    if(child->tid == pid){
      find = true;
      break;
    }
  }
  if (!find) return -1;
  if (!child->load_success) {
    syscall_wait(pid);
    return -1;
  }
  return pid;
}

int syscall_wait (tid_t pid){
  // Waits for the child process given as pid to terminate and retrieves the exit status.
  // It is possible for the parent process to wait for a child process that has already been terminated.
  // The kernel should retrieve the child’s exit status and pass it to the parent anyway.
  // If the child process has been terminated by the kernel, return status must be -1.
  // Wait must fail and return -1 immediately if any of the following conditions is true:
  // 	Pid does not refer to a direct child of the calling process. That is, if A spawns child B and B spawns child C, A cannot wait for C.
  // 	The process already called wait for the pid in the past. That is, the process can wait for a pid only once.
  // Processes may spawn any number of children. Your design should consider all the possible situation that can happen between parent and the child process.
  // Implementing this system call requires considerably more work than any of the rest.
  return process_wait(pid);
}

bool syscall_create(const char *file, unsigned initial_size){
  // Creates a new file with the name file and initialize its size with initial_size. Return true if successful, false otherwise.
  bool successful;
  if (!file){
    syscall_exit(-1);
  }
  is_valid_vaddr(file);
  lock_acquire(&file_sys_lock);
  successful = filesys_create(file, initial_size);
  lock_release(&file_sys_lock);
  return successful;
}

bool syscall_remove(const char *file){
  // Deletes the file called file. Returns true if successful, false otherwise. A file may be removed whether it is open or closed.
  // However, removing an open file does not close it.
  if (!file){
    syscall_exit(-1);
  }
  is_valid_vaddr(file);
  bool successful;
  lock_acquire(&file_sys_lock);
  successful = filesys_remove(file);
  lock_release(&file_sys_lock);
  return successful;
}

int syscall_open(const char *file){
  // open the file with name file. Returns a nonnegative integer number for the file descriptor, or -1 if unsuccessful.
  // File descriptors number 0 and 1 are reserved for the console, STDIN_FILENO, STDOU”T_FILENO, respectively. These numbers should not be used.
  // Each process has an independent set of file descriptors and file descriptors are not inherited to child processes.
  struct file *file_ptr;
  struct file_descriptor* temp;

  if (!file){
    syscall_exit(-1);
  }
  is_valid_vaddr(file);
  lock_acquire(&file_sys_lock);
  file_ptr = filesys_open(file);
  if(!file_ptr){
    lock_release(&file_sys_lock);
    return -1;
  }
  temp = (struct file_descriptor *)malloc(sizeof(struct file_descriptor));
  temp->fd = file_count++;
  temp->f_ptr = file_ptr;
  list_push_back(&thread_current()->fd_list, &temp->elem);

  lock_release(&file_sys_lock);
  return temp->fd;
}

int syscall_filesize(int fd){
  // Returns the size of opened file with fd.
  struct file* file_ptr;
  int fs;
  lock_acquire(&file_sys_lock);
  file_ptr = find_file_ptr(thread_current(), fd);
  if(!file_ptr){
    lock_release(&file_sys_lock);
    return -1;
  }
  fs = file_length(file_ptr);
  lock_release(&file_sys_lock);
  return fs;
}

int syscall_read(int fd, void *buffer, unsigned size){
  // Reads size bytes from the opend file and save the contents into buffer.
  // Returns the number of bytes that are acutally read. -1 should be returned if the system fails to read.
  // If 0 is given as fd, it should read from the keyboard using input_getc()
  struct file* file_ptr;
  unsigned i;
  int readed;

  check_buffer(buffer, size);

  if (fd == 0){
    for (i=0; i<size; i++){
      ((uint8_t *)buffer)[i] = input_getc();
    }
    return size;
  }

  lock_acquire(&file_sys_lock);
  file_ptr = find_file_ptr(thread_current(), fd);
  if (!file_ptr){
    lock_release(&file_sys_lock);
    return -1;
  }
  readed = file_read(file_ptr, buffer, size);
  lock_release(&file_sys_lock);
  return readed;
}

int syscall_write(int fd, const void *buffer, unsigned size){
  // Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written. 
  // Since the basic file system for this project does not support file growth, you should not write past the end-of-file.
  // If 1 is given as the fd, it should write to the console. You should use putbuf() to write things in the buffer to the console.
  struct file* file_ptr;
  int written;

  check_buffer(buffer, size);

  if (fd == 1){
    putbuf(buffer, size);
    return size;
  }

  lock_acquire(&file_sys_lock);
  file_ptr = find_file_ptr(thread_current(), fd);
  if (!file_ptr){
    lock_release(&file_sys_lock);
    return -1;
  }
  written = file_write(file_ptr, buffer, size);
  lock_release(&file_sys_lock);
  return written;
}

void syscall_seek (int fd, unsigned position){
  // Changes the next bytes to be read or written in open file fd to position.
  struct file* file_ptr;

  lock_acquire(&file_sys_lock);
  file_ptr = find_file_ptr(thread_current(), fd);
  if (!file_ptr){
    lock_release(&file_sys_lock);
    return;
  }
  file_seek(file_ptr, position);
  lock_release(&file_sys_lock);
  return;
}

unsigned syscall_tell (int fd){
  // Returns the position of the next byte to be read or written in open file fd.
  struct file* file_ptr;
  unsigned tl;

  lock_acquire(&file_sys_lock);
  file_ptr = find_file_ptr(thread_current(), fd);
  if (!file_ptr){
    lock_release(&file_sys_lock);
    return -1;
  }
  tl = file_tell(file_ptr);
  lock_release(&file_sys_lock);
  return tl;
}

void syscall_close (int fd){
  // Closes the file with fd. You should also close all of its open file descriptors as well.
  struct file_descriptor* temp;
  struct list_elem* next;
  struct list_elem* e;
  struct thread *cur;

  if (fd == 0 || fd == 1) return;

  cur = thread_current();

  lock_acquire(&file_sys_lock);
  for(e = list_begin(&cur->fd_list); e!=list_end(&cur->fd_list); e=next){
    next = list_next(e);
    temp = list_entry(e, struct file_descriptor, elem);
    if (temp->fd == fd){
      list_remove(&temp->elem);
      file_close(temp->f_ptr);
      free(temp);
    }
  }
  lock_release(&file_sys_lock);
  return;
}

struct file* find_file_ptr(struct thread *cur, int fd){
  struct file_descriptor* temp;
  struct list_elem* next;
  struct list_elem* e;

  for(e = list_begin(&cur->fd_list); e!=list_end(&cur->fd_list); e=next){
    next = list_next(e);
    temp = list_entry(e, struct file_descriptor, elem);
    if (temp->fd == fd){
      return temp->f_ptr;
    }
  }
  return NULL;
}

void check_four_byte(const void* vaddr){
  if (!pagedir_get_page(thread_current()->pagedir, vaddr) || !pagedir_get_page(thread_current()->pagedir, vaddr+1) || !pagedir_get_page(thread_current()->pagedir, vaddr+2) || !pagedir_get_page(thread_current()->pagedir, vaddr+3)){
    syscall_exit(-1);
  }
}

void is_valid_vaddr(const void* vaddr){
  if (vaddr < (void *)0x08048000 || is_kernel_vaddr(vaddr+3)){
    syscall_exit(-1);
  }
  else {
    check_four_byte(vaddr);
  }
}

void check_buffer(const void* buffer, unsigned size){
  unsigned i;
  char* temp = (char *)buffer;
  for (i = 0; i < size; i++)
  {
    if (temp < (char *)0x08048000 || is_kernel_vaddr(temp)) syscall_exit(-1);
    else if (!pagedir_get_page(thread_current()->pagedir, temp)) syscall_exit(-1);
    temp++;
  }
}