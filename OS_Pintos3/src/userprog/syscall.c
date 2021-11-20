#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include <stdlib.h>
struct lock filesys_lock;

static void syscall_handler(struct intr_frame *);

static void check_vaddr(const void *);

static void syscall_halt(void);
static pid_t syscall_exec(const char *);
static int syscall_wait(pid_t);
static bool syscall_create(const char *, unsigned);
static bool syscall_remove(const char *);
static int syscall_open(const char *);
static int syscall_filesize(int);
static int syscall_read(int, void *, unsigned);
static int syscall_write(int, const void *, unsigned);
static void syscall_seek(int, unsigned);
static unsigned syscall_tell(int);
static mapid_t syscall_mmap (int, void *);
static void syscall_munmap (mapid_t);

// pj3
struct mapping{
    void *page_addr;
    struct file *file;
    struct list_elem elem;
    mapid_t mapid;
    int page_cnt;
};

static void unmap(struct mapping *map);
static void vaddr_find_page(void **, bool);
// pj3

/* Registers the system call interrupt handler. */
void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

/* Pops the system call number and handles system call
   according to it. */
static void
syscall_handler(struct intr_frame *f)
{
    void *esp = f->esp;
    int syscall_num;

    check_vaddr(esp);
    check_vaddr(esp + sizeof(uintptr_t) - 1);
    syscall_num = *(int *)esp;

    switch (syscall_num)
    {
    case SYS_HALT:
    {
        syscall_halt();
        NOT_REACHED();
    }
    case SYS_EXIT:
    {
        int status;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        status = *(int *)(esp + sizeof(uintptr_t));

        syscall_exit(status);
        NOT_REACHED();
    }
    case SYS_EXEC:
    {
        char *cmd_line;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        cmd_line = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_exec(cmd_line);
        break;
    }
    case SYS_WAIT:
    {
        pid_t pid;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        pid = *(pid_t *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_wait(pid);
        break;
    }
    case SYS_CREATE:
    {
        char *file;
        unsigned initial_size;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));
        initial_size = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_create(file, initial_size);
        break;
    }
    case SYS_REMOVE:
    {
        char *file;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_remove(file);
        break;
    }
    case SYS_OPEN:
    {
        char *file;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        file = *(char **)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_open(file);
        break;
    }
    case SYS_FILESIZE:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_filesize(fd);
        break;
    }
    case SYS_READ:
    {
        int fd;
        void *buffer;
        unsigned size;

        check_vaddr(esp + sizeof(uintptr_t));
        // pj3
        vaddr_find_page(esp + 2 * sizeof(uintptr_t), true);
        // pj3
        check_vaddr(esp + 4 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_read(fd, buffer, size);
        break;
    }
    case SYS_WRITE:
    {
        int fd;
        void *buffer;
        unsigned size;

        check_vaddr(esp + sizeof(uintptr_t));
        // pj3
        vaddr_find_page(esp + 2 * sizeof(uintptr_t), false);
        // pj3
        check_vaddr(esp + 4 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_write(fd, buffer, size);
        break;
    }
    case SYS_SEEK:
    {
        int fd;
        unsigned position;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        position = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        syscall_seek(fd, position);
        break;
    }
    case SYS_TELL:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_tell(fd);
        break;
    }
    case SYS_CLOSE:
    {
        int fd;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));

        syscall_close(fd);
        break;
    }
    // pj3
    case SYS_MMAP:
    {
        int fd;
        void *addr;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 3 * sizeof(uintptr_t) - 1);
        fd = *(int *)(esp + sizeof(uintptr_t));
        addr = *(void **)(esp + 2 * sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_mmap(fd, addr);
        break;
    }
    case SYS_MUNMAP:
    {
        mapid_t map;

        check_vaddr(esp + sizeof(uintptr_t));
        check_vaddr(esp + 2 * sizeof(uintptr_t) - 1);
        map = *(mapid_t *)(esp + sizeof(uintptr_t));

        syscall_munmap(map);
        break;
    }
    // pj3
    default:
        syscall_exit(-1);
    }
}

// pj3
/*
    Checks user-provided virtual address. If it is invalid, terminates the current process. 
*/
static void check_vaddr(const void *vaddr)
{
    if (!vaddr || !is_user_vaddr(vaddr) || is_in_page(vaddr) == NULL){
        syscall_exit(-1);
    }
}

/*
    address에 들어있는 buffer addreee에 대한 page가 존재하는지 확인.
*/
static void vaddr_find_page(void **address, bool sys_read) {
    struct page *p;
    check_vaddr(*address);
    p = is_in_page(*address);
    if (p == NULL) {
        syscall_exit(-1);
    }
    if (p->read_only && sys_read){
        syscall_exit(-1);
    }
}
// pj3

struct lock *syscall_get_filesys_lock(void)
{
    return &filesys_lock;
}

/* Handles halt() system call. */
static void syscall_halt(void)
{
    shutdown_power_off();
}


/* Handles exit() system call. */
void syscall_exit(int status)
{
    struct process *pcb = thread_get_pcb();

// pj3
    struct thread *t = thread_current();
    struct list_elem *e, *next;
    struct mapping *map;

    // 모든 mapping unmap
    for (e = list_begin(&t->map_list); e != list_end(&t->map_list); e = next){
        next = list_next(e);
        map = list_entry(e, struct mapping, elem);
        unmap(map);
    }
// pj3

    pcb->exit_status = status;
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_exit();
}


/* Handles exec() system call. */
static pid_t syscall_exec(const char *cmd_line)
{
    pid_t pid;
    struct process *child;
    int i;

    check_vaddr(cmd_line);
    for (i = 0; *(cmd_line + i); i++)
        check_vaddr(cmd_line + i + 1);

    pid = process_execute(cmd_line);
    child = process_get_child(pid);

    if (!child || !child->is_loaded)
        return PID_ERROR;

    return pid;
}

/* Handles wait() system call. */
static int syscall_wait(pid_t pid)
{
    return process_wait(pid);
}

/* Handles create() system call. */
static bool syscall_create(const char *file, unsigned initial_size)
{
    bool success;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    lock_acquire(&filesys_lock);
    success = filesys_create(file, (off_t)initial_size);
    lock_release(&filesys_lock);

    return success;
}

/* Handles remove() system call. */
static bool syscall_remove(const char *file)
{
    bool success;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    lock_acquire(&filesys_lock);
    success = filesys_remove(file);
    lock_release(&filesys_lock);

    return success;
}

/* Handles open() system call. */
static int syscall_open(const char *file)
{
    struct file_descriptor_entry *fde;
    struct file *new_file;
    int i;

    check_vaddr(file);
    for (i = 0; *(file + i); i++)
        check_vaddr(file + i + 1);

    fde = palloc_get_page(0);
    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);

    new_file = filesys_open(file);
    if (!new_file)
    {
        palloc_free_page(fde);
        lock_release(&filesys_lock);

        return -1;
    }

    fde->fd = thread_get_next_fd();
    fde->file = new_file;
    list_push_back(thread_get_fdt(), &fde->fdtelem);

    lock_release(&filesys_lock);

    return fde->fd;
}

/* Handles filesize() system call. */
static int syscall_filesize(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);
    int filesize;

    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    filesize = file_length(fde->file);
    lock_release(&filesys_lock);

    return filesize;
}

/* Handles read() system call. */
static int syscall_read(int fd, void *buffer, unsigned size)
{
    struct file_descriptor_entry *fde;
    int bytes_read, i;

    for (i = 0; i < size; i++)
        check_vaddr(buffer + i);

    if (fd == 0)
    {
        unsigned i;

        for (i = 0; i < size; i++)
            *(uint8_t *)(buffer + i) = input_getc();

        return size;
    }

    fde = process_get_fde(fd);
    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    bytes_read = (int)file_read(fde->file, buffer, (off_t)size);
    lock_release(&filesys_lock);

    return bytes_read;
}

/* Handles write() system call. */
static int syscall_write(int fd, const void *buffer, unsigned size)
{
    struct file_descriptor_entry *fde;
    int bytes_written, i;

    for (i = 0; i < size; i++)
        check_vaddr(buffer + i);

    if (fd == 1)
    {
        putbuf((const char *)buffer, (size_t)size);

        return size;
    }

    fde = process_get_fde(fd);
    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    bytes_written = (int)file_write(fde->file, buffer, (off_t)size);
    lock_release(&filesys_lock);

    return bytes_written;
}

/* Handles seek() system call. */
static void syscall_seek(int fd, unsigned position)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);

    if (!fde)
        return;

    lock_acquire(&filesys_lock);
    file_seek(fde->file, (off_t)position);
    lock_release(&filesys_lock);
}

/* Handles tell() system call. */
static unsigned syscall_tell(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);
    unsigned pos;

    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    pos = (unsigned)file_tell(fde->file);
    lock_release(&filesys_lock);

    return pos;
}

/* Handles close() system call. */
void syscall_close(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);

    if (!fde)
        return;

    lock_acquire(&filesys_lock);
    file_close(fde->file);
    list_remove(&fde->fdtelem);
    palloc_free_page(fde);
    lock_release(&filesys_lock);
}

// pj3
/*
    unmap 함수
    인자로 주어진 mapping을 이용해서 이 mapping을 없앤다.
    dirty페이지는 write back 한다.
    그리고 할당된 page들도 삭제한다.
*/
static void unmap(struct mapping *map){
    struct page *p;
    struct thread *t = thread_current();
    // map list에서 제거
    list_remove(&map->elem);
    // dirty인지 확인하고 dirty이면 write back
    for (int i = 0; i < map->page_cnt; i++) {
        p = page_for_addr((map->page_addr) + (i * PGSIZE));
        if (p == NULL) PANIC("unmap error\n"); // because, umap이므로 page가 없을수가 없음
        if (pagedir_is_dirty(t->pagedir, (map->page_addr) + (i * PGSIZE))){
            lock_acquire (&filesys_lock);
            file_write_at(p->file, p->page_addr, p->file_length, p->file_offset); //마지막은 length만큼만 write back
            lock_release (&filesys_lock);
        }
    }
    // page deallocate
    for (int i = 0; i < map->page_cnt; i++) {
        page_destroy(page_for_addr((map->page_addr) + (i * PGSIZE)));
    }
}

/*
    syscall_mmap 함수
    우선 주어진 input들이 valid한지 검사한다.
    그리고 새로운 mapping을 생성해 파일 크기에 맞게 page들을 생성하고 값들을 넣어준다.
*/
static mapid_t syscall_mmap (int fd, void *addr) {
    struct mapping *map;
    struct file_descriptor_entry *fde;
    struct thread *t = thread_current();
    size_t offset = 0;
    off_t length;

    // 올바른 input들인지 검사
    if (addr == NULL || pg_ofs(addr) != 0) return -1;
    if (fd == 0 || fd == 1) return -1;
    fde = process_get_fde(fd);
    if (fde == NULL) return -1;

    lock_acquire(&filesys_lock);
    length = file_length(fde->file);
    if (length == 0) {
        lock_release(&filesys_lock);
        return -1;
    }
    lock_release(&filesys_lock);

    map = (struct mapping *)malloc(sizeof(struct mapping));
    if (map == NULL) return -1;

    map->mapid = t->next_mapid++;
    map->file = file_reopen (fde->file);
    map->page_addr = addr;
    map->page_cnt = 0;

    list_push_back(&t->map_list, &map->elem);
    
    while (length > 0){
        struct page *p = page_make_new(addr + offset, false);
        if (p == NULL){
            // 다른 page들과 겹침
            unmap(map);
            return -1;
        }
        p->file = map->file;
        p->file_offset = offset;
        p->file_length = length >= PGSIZE ? PGSIZE : length;
        offset += p->file_length;
        length -= p->file_length;
        map->page_cnt++;
    }
    return map->mapid;
}

/*
    syscall_unmap 함수
    mapid를 이용해 mapping을 찾고. unmap 함수를 호출해서 mapping을 삭제한다.
*/
static void syscall_munmap (mapid_t mapping) {
    struct thread *t = thread_current();
    struct list_elem *e;
    struct mapping *map;
    bool find = false;
    // mampping 찾고
    for (e = list_begin(&t->map_list); e != list_end(&t->map_list); e = list_next(e)){
        map = list_entry(e, struct mapping, elem);
        if (map->mapid == mapping){
            find = true;
            break;
        }
    }
    // 이거 일어나면 오류
    if (!find) PANIC("NO EXIST MAPPING!\n");
    // unmap
    unmap(map);
}
// pj3