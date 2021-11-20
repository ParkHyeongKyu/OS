#include "vm/swap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/vaddr.h"
#include <stdlib.h>
#include <stdio.h>
#include <bitmap.h>
static struct block *swap_device;
static struct bitmap *swap_bitmap;
static struct lock swap_lock;

/* Number of sectors per page. */
#define SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)

/*
    swap initial 함수
*/
void swap_init (void){
    swap_device = block_get_role(BLOCK_SWAP);
    if (swap_device != NULL) swap_bitmap = bitmap_create(block_size(swap_device) / SECTORS);
    if (swap_device == NULL || swap_bitmap == NULL) PANIC("swap initial fail\n");
    lock_init (&swap_lock);
}

/*
    swap in 함수
    swap 디스크에서 데이터를 찾아서, 할당된 frame으로 불러온다.
*/
void swap_in (struct page *p) {
    uint32_t i;
    lock_acquire (&swap_lock);
    for (i = 0; i < SECTORS; i++) block_read (swap_device, p->sector + i, p->frame->base_addr + i * BLOCK_SECTOR_SIZE);
    bitmap_reset (swap_bitmap, p->sector / SECTORS);
    p->sector = (block_sector_t)(-1);
    lock_release (&swap_lock);
}

/*
    swap out 함수
    swap 디스크에서 빈공간을 찾아서 page의 frame의 데이터를 block에 쓴다.
*/
bool swap_out (struct page *p) {
    ASSERT (p->frame != NULL);
    ASSERT (lock_held_by_current_thread (&p->frame->lock));

    size_t slot;
    size_t i;

    lock_acquire (&swap_lock);

    slot = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
    if (slot == BITMAP_ERROR) {
        lock_release (&swap_lock);
        return false;
    }

    p->sector = slot * SECTORS;

    for (i = 0; i < SECTORS; i++) {
        block_write (swap_device, p->sector + i, p->frame->base_addr + i * BLOCK_SECTOR_SIZE);
    }

    lock_release (&swap_lock);
    return true;
}