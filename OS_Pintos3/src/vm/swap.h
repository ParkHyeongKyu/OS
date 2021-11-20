#include "vm/page.h"

#ifndef VM_SWAP
#define VM_SWAP

void swap_init (void);
void swap_in (struct page *p);
bool swap_out (struct page *p);

#endif