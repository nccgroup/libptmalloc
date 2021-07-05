#include <stdio.h>
#include <stdlib.h>

# define offsetof(type,ident) ((size_t)&(((type*)0)->ident))

//glibc-2.27/sysdeps/generic/malloc-alignment.h
#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
			  ? __alignof__ (long double) : 2 * SIZE_SZ)
//glibc-2.27/sysdeps/i386/malloc-alignment.h
//#define MALLOC_ALIGNMENT 16

//glibc-2.27/malloc/malloc-internal.h
# define INTERNAL_SIZE_T size_t
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)

//glibc-2.27/malloc/malloc.c
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)
# define TCACHE_MAX_BINS		64
# define MAX_TCACHE_SIZE	tidx2usize (TCACHE_MAX_BINS-1)
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)

#define NBINS             128
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)

#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)

#define largebin_index_32(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 38) ?  56 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

#define largebin_index_32_big(sz)                                            \
  (((((unsigned long) (sz)) >> 6) <= 45) ?  49 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

// XXX It remains to be seen whether it is good to keep the widths of
// XXX the buckets the same or whether it should be scaled by a factor
// XXX of two as well.
#define largebin_index_64(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

#define largebin_index(sz) \
  (SIZE_SZ == 8 ? largebin_index_64 (sz)                                     \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                     \
   : largebin_index_32 (sz))

int main()
{
    printf("SIZE_SZ = 0x%zx\n", SIZE_SZ); //0x8 on 64-bit, 0x4 on 32-bit
    printf("MALLOC_ALIGNMENT = 0x%zx\n", MALLOC_ALIGNMENT); //0x10 on 64-bit, 0x8 on 32-bit
    printf("MINSIZE = 0x%lx\n", MINSIZE); //0x20 on 64-bit, 0x10 on 32-bit
#if 0
  // tcache stuff
    printf("tidx2usize(0) = 0x%lx\n", tidx2usize(0));
    printf("tidx2usize(1) = 0x%lx\n", tidx2usize(1));
    printf("tidx2usize(2) = 0x%lx\n", tidx2usize(2));
    printf("MAX_TCACHE_SIZE = 0x%lx\n", MAX_TCACHE_SIZE);
    printf("csize2tidx(0x18) = %ld\n", csize2tidx(0x18));
    printf("csize2tidx(0x20) = %ld\n", csize2tidx(0x20));
    printf("csize2tidx(0x21) = %ld\n", csize2tidx(0x21));
    printf("csize2tidx(0x28) = %ld\n", csize2tidx(0x28));
    printf("csize2tidx(0x30) = %ld\n", csize2tidx(0x30));
    printf("csize2tidx(0x160) = %ld\n", csize2tidx(0x160));
    printf("csize2tidx(0x190) = %ld\n", csize2tidx(0x190));
#endif
#if 1
    printf("MIN_LARGE_SIZE = 0x%zx\n", MIN_LARGE_SIZE); //0x400 on 64-bit, 0x200 on 32-bit
    unsigned int last_index = 64; // first index in large bin
    unsigned int index;
    for (unsigned size = MIN_LARGE_SIZE; size < 0x200000; size+= 0x1) {
      index = largebin_index(size);
      if (index != last_index) {
        //printf("largebin_index(0x%x) -> large bin %d\n", size, index);
        //printf("large bin %d: chunk sz <= 0x%zx\n", last_index, 2 * SIZE_SZ + size);
        // Generate some code we can use in libptmalloc
        printf("elif index == %d: return 0x%zx\n", last_index, 2 * SIZE_SZ + size);
        last_index = index;
      }
    }
#endif
    return 0;
}