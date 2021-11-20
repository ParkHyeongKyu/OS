#include "devices/block.h"
#include <hash.h>
#include "filesys/off_t.h"
#include "userprog/process.h"
#ifndef PAGE_H
#define PAGE_H

#define STACK_MAX (8 * 1024 * 1024) //8MB

struct page{
  void *page_addr;
  struct frame *frame;
  struct thread *t;
  struct hash_elem h_elem;
  block_sector_t sector;
  struct file *file;
  size_t file_offset;
  off_t file_length;
  bool read_only;
};

struct page *page_for_addr(void *addr);
struct page *is_in_page(void *addr);
bool lazy_load(void *faulted_addr);
struct page *page_make_new(void *vaddr, bool read_only);
void page_destroy(struct page *p);

hash_hash_func page_hash;
hash_less_func page_less;
void free_all_page(struct hash_elem *p_, void *aux);

#endif