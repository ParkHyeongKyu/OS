#include "vm/swap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "threads/malloc.h"
#include "userprog/syscall.h"

/*
    address에 맞는 page를 찾아서 찾으면 그 page return
    만약 address가 stack growth라면 (== stack growth 이면 page가 없음), valid한지 확인하고 stack growth
    page가 없다면 NULL return
*/
struct page *page_for_addr(void *addr){
    ASSERT(addr != NULL);

    struct page p;
    struct hash_elem *e;
    p.page_addr = (void *)pg_round_down(addr);

    // find page
    e = hash_find(thread_current()->page_table, &p.h_elem);
    if (e!=NULL) return hash_entry(e, struct page, h_elem);

    // not find
    // stack growth
    if ((addr > PHYS_BASE - STACK_MAX) && addr >= (thread_current()->saved_esp - 32)){
        // valid한 stack growth
        return page_make_new(p.page_addr, false);
    }

    // not find, not stack growth
    return NULL;
}


/*
    address에 맞는 page를 찾아서 찾으면 그 page return
    만약 address에 맞는 page가 없다면 NULL return
*/
struct page *is_in_page(void *addr){
    ASSERT(addr != NULL);

    struct page p;
    struct hash_elem *e;
    p.page_addr = (void *)pg_round_down(addr);

    // find page
    e = hash_find(thread_current()->page_table, &p.h_elem);
    if (e!=NULL) return hash_entry(e, struct page, h_elem);

    // not find
    return NULL;
}

/*
    lazy_loading
    if page's frame is NULL, find one free frame.
    if the page was swapped out, then swap in
    elif the page is one part of file, then load it
    else (== stack growth), then provide 0 space
*/
bool lazy_load(void *faulted_addr){
    if (faulted_addr == NULL || !is_user_vaddr(faulted_addr)){
        return false;
    }

    bool result = false;
    struct page *p = page_for_addr(faulted_addr);
    if (p==NULL) return false;

    if (p->frame == NULL){ // 맨 처음 or swap out 된 상태
        // 빈 frame 하나 받고
        p->frame = frame_find_free_and_lock(p);
        if (p->frame == NULL) return false;

        // install page
        result = install_page(p->page_addr, p->frame->base_addr, !p->read_only);
        if (result == false) return false;

        // lazy load
        if (p->sector != (block_sector_t) -1) {
            // swap out 된 page swap in
            swap_in(p);
        }
        else if(p->file != NULL) {
            // load from disk
            off_t read_bytes = file_read_at (p->file, p->frame->base_addr, p->file_length, p->file_offset);
            memset(p->frame->base_addr + read_bytes, 0, PGSIZE - read_bytes);
            if (read_bytes != p->file_length) PANIC("file read failed!");
        }
        else {
            // provide zero space
            memset(p->frame->base_addr, 0, PGSIZE);
        }
    }
    return result;
}

/*
    새로운 page 생성
    성공하면 page의 address return
    실패하면 NULL return
*/
struct page *page_make_new(void *vaddr, bool read_only){
    ASSERT(pg_ofs(vaddr) == 0);

    struct thread *t = thread_current();
    struct page *p = (struct page *)malloc(sizeof(struct page));
    if (p != NULL){
        p->page_addr = vaddr;
        p->frame = NULL;
        p->t = t;
        p->read_only = read_only;
        p->sector = (block_sector_t)(-1);
        p->file = NULL;

        // hash에 삽입
        if (hash_insert(t->page_table, &p->h_elem) != NULL){
            // already inserted
            free(p);
            p = NULL;
        }
    }
    return p;
}

/*
    page - frame page에 할당된 frame을 해제하고, page 삭제
*/
void page_destroy(struct page *p){
    frame_free_and_unlock(p->frame);
    if (hash_delete(thread_current()->page_table, &p->h_elem) == NULL) PANIC("hash_delete_fail!\n");
    free (p);
}

/*
    해싱 함수
*/
unsigned page_hash (const struct hash_elem *e, void *aux UNUSED) {
    const struct page *p = hash_entry (e, struct page, h_elem);
    return ((uintptr_t)p->page_addr) >> PGBITS;
}

/*
    해싱 함수
*/
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
    const struct page *a = hash_entry (a_, struct page, h_elem);
    const struct page *b = hash_entry (b_, struct page, h_elem);
    return a->page_addr < b->page_addr;
}

/*
    해싱 함수
*/
void free_all_page(struct hash_elem *p_, void *aux UNUSED){
    struct page *p = hash_entry (p_, struct page, h_elem);
    if (p->frame) frame_free_and_unlock(p->frame);
    free (p);
}
