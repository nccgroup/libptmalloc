#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h> 
#include <stdbool.h>

#define SEED 1337

#if defined(TESTDOC)
#define MAX_COUNT_ALLOCATIONS 400
#define MAX_COUNT_ALLOCATIONS_FASTBINS 80
#else
#if defined(TEST1) || defined(TEST1B)
#define MAX_COUNT_ALLOCATIONS 4096
#define MAX_COUNT_ALLOCATIONS_FASTBINS 100
#else
#if defined(TEST2)
#define MAX_COUNT_ALLOCATIONS 4096
#define MAX_COUNT_ALLOCATIONS_FASTBINS 1000
#else
#define MAX_COUNT_ALLOCATIONS 10
#define MAX_COUNT_ALLOCATIONS_FASTBINS 10
#endif
#endif
#endif

char* buffers[MAX_COUNT_ALLOCATIONS];
unsigned int sizes[MAX_COUNT_ALLOCATIONS];
static unsigned int idx = 0; // available idx to use for next alloc

// We track freed sizes so we know what sizes to realloc before we free them again
unsigned int sizes_freed[MAX_COUNT_ALLOCATIONS]; // upper bound size
static unsigned int idx_freed = 0; // available idx to use for next freed

#if defined(TEST1) || defined(TEST1B) || defined(TESTDOC)
char* buffers2[MAX_COUNT_ALLOCATIONS_FASTBINS];
static unsigned int idx2 = 0; // available idx to use for next alloc
#endif

static unsigned int total_cnt_frees = 0;
static unsigned int total_cnt_allocs = 0;

char letter = 'A';

char next_letter() {
    if (letter == 'Z') {
        letter = 'A';
    } else {
        letter += 1;
    }
    return letter;
}

void *f1(void *x);
void *f2(void *x);

/* Returns an integer in the range [0, n].
 *
 * Uses rand(), and so is affected-by/affects the same seed.
 * Source: https://stackoverflow.com/questions/822323/how-to-generate-a-random-int-in-c
 */
int randint(int n) {
    if ((n - 1) == RAND_MAX) {
        return rand();
    } else {
        // Supporting larger values for n would requires an even more
        // elaborate implementation that combines multiple calls to rand()
        assert (n <= RAND_MAX);

        // Chop off all of the values that would cause skew...
        int end = RAND_MAX / n; // truncate skew
        assert (end > 0);
        end *= n;

        // ... and ignore results from rand() that fall above that limit.
        // (Worst case the loop condition should succeed 50% of the time,
        // so we can expect to bail out of this loop pretty quickly.)
        int r;
        while ((r = rand()) >= end);
        return r % n;
    }
}

//https://stackoverflow.com/questions/2509679/how-to-generate-a-random-integer-number-from-within-a-range
unsigned int rand_interval(unsigned int min, unsigned int max)
{
    unsigned int r;
    const unsigned int range = 1 + max - min;
    const unsigned int buckets = RAND_MAX / range;
    const unsigned int limit = buckets * range;

    /* Create equal size buckets all in a row, then fire randomly towards
     * the buckets until you land in one of them. All buckets are equally
     * likely. If you land off the end of the line of buckets, try again. */
    do
    {
        r = (unsigned int)rand();
    } while (r >= limit);

    return min + (r / buckets);
}

// When trying to access "tcache" global variable in gdb, we get this error:
// ```
// Cannot find thread-local storage for process 109057, shared library /usr/lib/debug/lib/x86_64-linux-gnu/libc-2.27.so:
// Cannot find thread-local variables on this target
// ```
// It seems it is related to the executable not being linked to pthreads.
// So the trick we use is to force using pthreads functions and it does the job lol
//
// This is code from https://unix.stackexchange.com/questions/33396/gcc-cant-link-to-pthread
#ifndef TEST1B
void create_threads()
{
    pthread_t f2_thread, f1_thread; 

    int i1,i2;
    i1 = 1;
    i2 = 2;
    pthread_create(&f1_thread, NULL, f1, &i1);
    pthread_create(&f2_thread, NULL, f2, &i2);
    pthread_join(f1_thread, NULL);
    pthread_join(f2_thread, NULL);
}

void *f1(void *x){
    int i;
    i = *(int*)x;
    //sleep(1);
    printf("f1: %d\n", i);

    // for (i = 0; i < 10; i++) {
    //     test1_alloc();
    // }
    pthread_exit(0); 
}

void *f2(void *x){
    int i;
    i = *(int*)x;
    //sleep(1);
    printf("f2: %d\n", i);
    pthread_exit(0); 
}
#endif

// several functions so we have a backtrace to save in metadata
void __attribute__((optimize("O0"))) func3()
{
    asm("int $3");  // so we can analyse in gdb
}

void __attribute__((optimize("O0"))) func2()
{
    func3();
}

void __attribute__((optimize("O0")))  func1()
{
    func2();
}


#if defined(TEST1) || defined(TEST1B) || defined(TESTDOC)
void test1_alloc()
{
    unsigned int size = 0x0;
    switch (randint(4))
    {
    case 0:
        size = 0x80; // force tcache size
        break;
    case 1:
        size = 0xa8; // force fastbin size on 64-bit (?)
        break;
    case 2:
        size = 0x400;
        break;
    case 3:
        size = 0x2000;
        break;
    case 4:
        size = 0x20000;
        break;
    }
    unsigned int alloc_size = randint(size);
    buffers[idx] = malloc(alloc_size);
    sizes[idx] = alloc_size;
    memset(buffers[idx], next_letter(), alloc_size);
    idx++;
    printf("+");
    total_cnt_allocs += 1;
}

void test1_free()
{
    unsigned int i;
    unsigned int free_idx = randint(idx-1);
    free(buffers[free_idx]);
    buffers[free_idx] = NULL;
    sizes_freed[idx_freed++] = sizes[free_idx];
    // shift the remaining pointers so it is easier
    // to track which ones are not freed yet
    for (i = free_idx; i <= idx-1; i++) {
        buffers[i] = buffers[i+1];
        sizes[i] = sizes[i+1];
    }
    idx--;
    printf("-");
    total_cnt_frees += 1;
}

void test1_realloc()
{
    unsigned int i;
    unsigned int realloc_idx = randint(idx_freed-1);
    unsigned int alloc_size = sizes_freed[realloc_idx];
    buffers[idx] = malloc(alloc_size);
    memset(buffers[idx], next_letter(), alloc_size);
    idx++;
    // shift the remaining pointers so it is easier
    // to track which ones are not freed yet
    for (i = realloc_idx; i <= idx_freed-1; i++) {
        sizes_freed[i] = sizes_freed[i+1];
    }
    idx_freed--;
    printf("*");
    total_cnt_allocs += 1;
}

void test1_alloc2()
{
    // force fastbin allocs
    unsigned int alloc_size = randint(0xa0);
    buffers2[idx2] = malloc(alloc_size);
    memset(buffers2[idx2], next_letter(), alloc_size);
    idx2++;
    printf("^");
    total_cnt_allocs += 1;
}

void test1_free2()
{
    unsigned int i;
    unsigned int free_idx = randint(idx2-1);
    free(buffers2[free_idx]);
    buffers2[free_idx] = NULL;
    // shift the remaining pointers so it is easier
    // to track which ones are not freed yet
    for (i = free_idx; i <= idx2-1; i++) {
        buffers2[i] = buffers2[i+1];
    }
    idx2--;
    printf("0");
    total_cnt_frees += 1;
}

void test1()
{
    unsigned int i;
    unsigned int count_allocs = rand_interval(1, MAX_COUNT_ALLOCATIONS);
    unsigned int count_frees = rand_interval(1, count_allocs);
    unsigned int divide_reallocs = rand_interval(1, 10);
    unsigned int count_reallocs = rand_interval(1, count_frees/divide_reallocs);

#if defined(TESTDOC)
    unsigned int count_allocs_fastbins = MAX_COUNT_ALLOCATIONS_FASTBINS;
    unsigned int count_frees_fastbins = MAX_COUNT_ALLOCATIONS_FASTBINS;
#else
    unsigned int count_allocs_fastbins = rand_interval(1, MAX_COUNT_ALLOCATIONS_FASTBINS);
    unsigned int count_frees_fastbins = rand_interval(1, count_allocs_fastbins);
#endif

    for (i = 0; i < count_allocs; i++) {
        test1_alloc();
    }
    // Free so some chunks are put in unsorted bin
    for (i = 0; i < count_frees; i++) {
        test1_free();
    }
    // Chunks are not placed in regular bins until some of them have been given
    // one chance to be used in malloc
    for (i = 0; i < count_reallocs; i++) {
        test1_realloc();
    }

    // We allocate fastbins after the above as otherwise we won't have anything
    // left in the fastbin as would have been moved to regular bins
    for (i = 0; i < count_allocs_fastbins; i++) {
        test1_alloc2();
    }
    for (i = 0; i < count_frees_fastbins; i++) {
        test1_free2();
       if (idx2 == 0) {
           printf("WARNING: too many frees detected!\n");
           break;
       }
    }
    printf("\n");
	printf("[+] Count allocs: %d done\n", count_allocs);
	printf("[+] Count frees: %d done\n", count_frees);
	printf("[+] Count reallocs: %d done\n", count_reallocs);
	printf("[+] Count allocs fastbins: %d done\n", count_allocs_fastbins);
	printf("[+] Count free fastbins: %d done\n", count_frees_fastbins);
	printf("[+] Total allocs: %d done\n", total_cnt_allocs);
	printf("[+] Total allocs: %d done\n", total_cnt_frees);
}
#else
#ifdef TEST2
void test2_alloc()
{
    unsigned int multiplicator = rand_interval(1, 20);
    unsigned int alloc_size = randint(multiplicator*0x8000);
    buffers[idx] = malloc(alloc_size);
    sizes[idx] = alloc_size;
    memset(buffers[idx], next_letter(), alloc_size);
    idx++;
    printf("+");
    total_cnt_allocs += 1;
}

void test2_free(unsigned int free_idx)
{
    free(buffers[free_idx]);
    buffers[free_idx] = NULL;
    sizes_freed[idx_freed++] = sizes[free_idx];
    // Set the size to 0x0 so it is easier
    // to track which ones are not freed yet
    sizes[free_idx] = 0x0;
    printf("-");
    total_cnt_frees += 1;
}

void test2_realloc()
{
    unsigned int i;
    unsigned int realloc_idx = randint(idx_freed-1);
    unsigned int alloc_size = sizes_freed[realloc_idx];
    buffers[idx] = malloc(alloc_size);
    memset(buffers[idx], next_letter(), alloc_size);
    idx++;
    // shift the remaining pointers so it is easier
    // to track which ones are not freed yet
    for (i = realloc_idx; i <= idx_freed-1; i++) {
        sizes_freed[i] = sizes_freed[i+1];
    }
    idx_freed--;
    printf("*");
    total_cnt_allocs += 1;
}

void test2()
{
    unsigned int i;
    unsigned int count_allocs = randint(MAX_COUNT_ALLOCATIONS);
    unsigned int count_frees = randint(count_allocs);
    unsigned int divide_reallocs = rand_interval(1, 10);
    unsigned int count_reallocs = randint(count_frees/divide_reallocs);

    for (i = 0; i < count_allocs; i++) {
        test2_alloc();
    }
    // Free so some large chunks are put in unsorted bin
    // += 2 to do every other chunk to avoid coalescing
    for (i = 0; i < count_frees; i+=2) {
        test2_free(i);
    }
    // Chunks are not placed in regular bins until some of them have been given
    // one chance to be used in malloc
    for (i = 0; i < count_reallocs; i++) {
        test2_realloc();
    }
}
#endif
#endif

int main(int argc, char* argv[])
{
#ifndef TEST1B
    create_threads();
#endif

    // deterministic
    unsigned int seed = SEED;
    if (argc >= 2) {
        // We support passing the seed as from experience this influences a lot
        // the allocations happening so it eases adapting the bins we can analyse
        seed = atoi(argv[1]);
    }
    srand(seed);

#if defined(TEST1) || defined(TEST1B) || defined(TESTDOC)
    test1();
#else
#ifdef TEST2
    test2();
#endif
#endif

	func1();
	printf("[+] Exiting process\n");
	exit(1);
}