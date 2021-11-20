#include "vm/swap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <stdlib.h>
#include "threads/malloc.h"
#include "userprog/pagedir.h"

static struct list frame_list;
static struct list_elem *frame_pos;

static struct lock frame_sys_lock;


/* initialize frame table */
void frame_table_init(void){
    void *base_ptr;
    struct frame *temp;

    list_init(&frame_list);
    lock_init(&frame_sys_lock);

    while ((base_ptr = palloc_get_page(PAL_USER)) != NULL){
        temp = malloc(sizeof(struct frame));
        temp->base_addr = base_ptr;
        temp->page = NULL;
        lock_init(&temp->lock);
        list_push_back(&frame_list, &temp->elem);
    }
    frame_pos = list_front(&frame_list);
}

/* for clock algorithm */
static struct frame *frame_get_next(void){
    struct list_elem *next;
    if (frame_pos == list_back(&frame_list)) next = list_front(&frame_list);
    else next = list_next(frame_pos);
    frame_pos = next;
    return list_entry(frame_pos, struct frame, elem);
}

/* find or make free page and lock */
/* just provide free frame not install_page */
struct frame *frame_find_free_and_lock(struct page *page){
    ASSERT(page != NULL);

    struct list_elem *e;
    struct frame *f;
    bool result;

    lock_acquire(&frame_sys_lock);

    // find free page
    for (e = list_begin(&frame_list); e != list_end(&frame_list); e = list_next(e)){
        f = list_entry(e, struct frame, elem);
        if (lock_held_by_current_thread(&f->lock)) continue;
        if (!lock_try_acquire(&f->lock)) continue;
        // if find free page, allocate and return
        if (f->page == NULL){
            // page에서 page_number를 구해서 temp의 page_number에 저장한다.
            f->page = page;
            ASSERT(lock_held_by_current_thread(&f->lock));
            lock_release(&frame_sys_lock);
            return f;
        }
        lock_release(&f->lock);
    }

    // if fail to find free frame, then choose victim
    // 희생자 선정하고, swap out시켜서 free frame을 확보하고, 그리고 거기에 page allocation.
    // not yet
    f = frame_get_next();
    pagedir_set_accessed(thread_current()->pagedir, f->base_addr, false);

    while (true) {
        if (!pagedir_is_accessed(thread_current()->pagedir, f->base_addr)){

            result = swap_out(f->page);
            if (!result) return NULL;

            lock_release(&f->lock); // lock이 이미 다른 process에 들려있었으므로 풀어주고
            pagedir_clear_page(f->page->t->pagedir, f->page->page_addr);
            f->page->frame = NULL; // page - frame 매칭 해제

            f->page = page; // new match
            lock_acquire(&f->lock);
            ASSERT(lock_held_by_current_thread(&f->lock));
            lock_release(&frame_sys_lock);
            return f;
        }
        f = frame_get_next();
    }
}

/* clear and unlock */
void frame_free_and_unlock(struct frame *f){
    ASSERT(lock_held_by_current_thread(&f->lock));
    
    lock_acquire(&frame_sys_lock);

    lock_release(&f->lock);
    pagedir_clear_page(f->page->t->pagedir, f->page->page_addr);
    f->page->frame = NULL;
    f->page = NULL;

    lock_release(&frame_sys_lock);
}
