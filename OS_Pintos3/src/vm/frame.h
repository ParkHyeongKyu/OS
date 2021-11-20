#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/synch.h"

#ifndef FRAME
#define FRAME

struct frame{
    void *base_addr;
    struct page *page;
    struct lock lock;
    struct list_elem elem;
};

void frame_table_init(void);
struct frame *frame_find_free_and_lock(struct page *page);
void frame_free_and_unlock(struct frame *f);

#endif