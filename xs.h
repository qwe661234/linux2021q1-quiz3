#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

enum {
    CSTR_PERMANENT = 1,
    CSTR_INTERNING = 2,
    CSTR_ONSTACK = 4,
};

#define TICK(X) clock_t X = clock()
#define TOCK(X) clock() - X
#define PTIME(X) printf("%ld\n", X)

#define MAX_STR_LEN_BITS (54)
#define MAX_STR_LEN ((1UL << MAX_STR_LEN_BITS) - 1)
#define LARGE_STRING_LEN 256

#define XS_INTERNING_SIZE (32)
#define XS_STACK_SIZE (16)
#define INTERNING_POOL_SIZE 1024
#define HASH_START_SIZE 16

typedef union {
    /* allow strings up to 15 bytes to stay on the stack
     * use the last byte as a null terminator and to store flags
     * much like fbstring:
     * https://github.com/facebook/folly/blob/master/folly/docs/FBString.md
     */
    /* store short string */ 
    char data[16];
    
    struct {
        uint32_t hash_size;
        uint16_t type;
        uint16_t ref;
        uint8_t filler[7],
            /* how many free bytes in this stack allocated string
             * same idea as fbstring
             */
            /* how many length are left for short string */
            space_left : 4,
            /* if it is on heap, set to 1 */
            is_ptr : 1, is_large_string : 1, flag2 : 1, flag3 : 1;
    };

    /* heap allocated */
    struct {
        char *ptr;
        /* supports strings up to 2^MAX_STR_LEN_BITS - 1 bytes */
        size_t size : MAX_STR_LEN_BITS,
                      /* capacity is always a power of 2 (unsigned)-1 */
                      capacity : 6;
        /* the last 4 bits are important flags */
    };
    
} xs;

struct __xs_node {
    char buffer[XS_INTERNING_SIZE];
    xs str;
    struct __xs_node *next;
};

struct __xs_pool {
    struct __xs_node node[INTERNING_POOL_SIZE];
};

struct __xs_interning {
    int lock;
    int index;
    unsigned size;
    unsigned total;
    struct __xs_node **hash;
    struct __xs_pool *pool;
};

static struct __xs_interning __xs_ctx;

#define CSTR_LOCK()                                               \
    ({                                                            \
        while (__sync_lock_test_and_set(&(__xs_ctx.lock), 1)) { \
        }                                                         \
    })
#define CSTR_UNLOCK() ({ __sync_lock_release(&(__xs_ctx.lock)); })

static void *xalloc(size_t n)
{
    void *m = malloc(n);
    if (!m)
        exit(-1);
    return m;
}

static inline bool xs_is_ptr(const xs *x) { return x->is_ptr; } 

static inline bool xs_is_large_string(const xs *x) 
{
    return x->is_large_string;
}

static inline size_t xs_size(const xs *x) 
{
    return xs_is_ptr(x) ? x->size : 15 - x->space_left;
}

static inline char *xs_data(const xs *x)
{
    /* short string */
    if (!xs_is_ptr(x))
        return (char *) x->data;
    /* large string */
    if (xs_is_large_string(x))
        return (char *) (x->ptr + 4);
    return (char *) x->ptr;
}

/* the space allocating for heap */
static inline size_t xs_capacity(const xs *x)
{
    return xs_is_ptr(x) ? ((size_t) 1 << x->capacity) - 1 : 15;
}

static inline void xs_set_refcnt(const xs *x, int val)
{
    *((int *) ((size_t) x->ptr)) = val;
}

static inline void xs_inc_refcnt(const xs *x)
{
    if (xs_is_large_string(x))
        ++(*(int *) ((size_t) x->ptr));
}

static inline int xs_dec_refcnt(const xs *x)
{
    if (!xs_is_large_string(x))
        return 0;
    return --(*(int *) ((size_t) x->ptr));
}

static inline int xs_get_refcnt(const xs *x)
{
    if (!xs_is_large_string(x))
        return 0;
    return *(int *) ((size_t) x->ptr);
}

#define xs_literal_empty() \
    (xs) { .space_left = 15 }

/* lowerbound (floor log2) */
static inline int ilog2(uint32_t n) { return 32 - __builtin_clz(n) - 1; }

static void xs_allocate_data(xs *x, size_t len, bool reallocate)
{
    /* Medium string */
    if (len < LARGE_STRING_LEN) {
        x->ptr = reallocate ? realloc(x->ptr, (size_t) 1 << x->capacity)
                            : malloc((size_t) 1 << x->capacity);
        return;
    }

    /* Large string */
    x->is_large_string = 1;

    /* The extra 4 bytes are used to store the reference count */
    x->ptr = reallocate ? realloc(x->ptr, (size_t)(1 << x->capacity) + 4)
                        : malloc((size_t)(1 << x->capacity) + 4);

    xs_set_refcnt(x, 1);
}

//change
xs *xs_new(xs *x, const void *p)
{
    *x = xs_literal_empty();
    size_t len = strlen(p) + 1;
    if (len > 16) {
        x->capacity = ilog2(len) + 1;
        x->size = len - 1;
        x->is_ptr = true;
        xs_allocate_data(x, x->size, 0);
        memcpy(xs_data(x), p, len);
    } else {
        memcpy(x->data, p, len);
        x->space_left = 15 - (len - 1);
    }
    return x;
}

/* Memory leaks happen if the string is too long but it is still useful for
 * short strings.
 */
#define xs_tmp(x)                                                   \
    ((void) ((struct {                                              \
         _Static_assert(sizeof(x) <= MAX_STR_LEN, "it is too big"); \
         int dummy;                                                 \
     }){1}),                                                        \
     xs_new(&xs_literal_empty(), x))

/* grow up to specified size */
xs *xs_grow(xs *x, size_t len)
{
    char buf[16];

    if (len <= xs_capacity(x))
        return x;

    /* Backup first */
    if (!xs_is_ptr(x))
        memcpy(buf, x->data, 16);

    x->is_ptr = true;
    x->capacity = ilog2(len) + 1;

    if (xs_is_ptr(x)) {
        xs_allocate_data(x, len, 1);
    } else {
        xs_allocate_data(x, len, 0);
        memcpy(xs_data(x), buf, 16);
    }
    return x;
}

static inline xs *xs_newempty(xs *x)
{
    *x = xs_literal_empty();
    return x;
}

static inline xs *xs_free(xs *x)
{
    if (xs_is_ptr(x) && xs_dec_refcnt(x) <= 0)
        free(x->ptr);
    return xs_newempty(x);
}

static inline void insert_node(struct __xs_node **hash,
                               int sz,
                               struct __xs_node *node)
{
    uint32_t h = node->str.hash_size;
    int index = h & (sz - 1);
    node->next = hash[index];
    hash[index] = node;
}

static void expand(struct __xs_interning *si)
{
    unsigned new_size = si->size * 2;
    if (new_size < HASH_START_SIZE)
        new_size = HASH_START_SIZE;

    struct __xs_node **new_hash =
        xalloc(sizeof(struct __xs_node *) * new_size);
    memset(new_hash, 0, sizeof(struct __xs_node *) * new_size);

    for (unsigned i = 0; i < si->size; ++i) {
        struct __xs_node *node = si->hash[i];
        while (node) {
            struct __xs_node *tmp = node->next;
            insert_node(new_hash, new_size, node);
            node = tmp;
        }
    }

    free(si->hash);
    si->hash = new_hash;
    si->size = new_size;
}

static xs *interning(struct __xs_interning *si,
                         const char *cstr,
                         size_t sz,
                         uint32_t hash)
{
    if (!si->hash)
        return NULL;

    int index = (int) (hash & (si->size - 1));
    struct __xs_node *n = si->hash[index];
    while (n) {
        if (n->str.hash_size == hash) {
            if (!strcmp(xs_data(&n->str), cstr))
                return &n->str;
        }
        n = n->next;
    }
    // 80% (4/5) threshold
    if (si->total * 5 >= si->size * 4)
        return NULL;
    if (!si->pool) {
        si->pool = xalloc(sizeof(struct __xs_pool));
        si->index = 0;
    }
    n = &si->pool->node[si->index++];
    memcpy(n->buffer, cstr, sz);
    n->buffer[sz] = 0;

    n->str.hash_size = hash;
    n->str.type = CSTR_INTERNING;
    n->str.ref = 0;
    
    size_t len = strlen(n->buffer);
    if (len < 16) {
        strncpy(n->str.data, n->buffer, len);
        n->str.space_left = 15 - (len - 1); 
    }else{
        n->str.capacity = ilog2(len) + 1;
        n->str.size = len - 1;
        n->str.is_ptr = true;
        xs_allocate_data(&n->str, n->str.size, 0);
        memcpy(xs_data(&n->str), n->buffer, len);
    }
    

    n->next = si->hash[index];
    si->hash[index] = n;

    return &n->str;
}

static xs *cstr_interning(const char *cstr, size_t sz, uint32_t hash)
{
    xs *ret;
    CSTR_LOCK();
    ret = interning(&__xs_ctx, cstr, sz, hash);
    if (!ret) {
        expand(&__xs_ctx);
        ret = interning(&__xs_ctx, cstr, sz, hash);
    }
    ++__xs_ctx.total;
    CSTR_UNLOCK();
    return ret;
}

static inline uint32_t hash_blob(const char *buffer, size_t len)
{
    const uint8_t *ptr = (const uint8_t *) buffer;
    size_t h = len;
    size_t step = (len >> 5) + 1;
    for (size_t i = len; i >= step; i -= step)
        h = h ^ ((h << 5) + (h >> 2) + ptr[i - 1]);
    return h == 0 ? 1 : h;
}

static size_t xs_hash(xs *s)
{
    if (s->type == CSTR_ONSTACK)
        return hash_blob(xs_data(s), s->hash_size);
    if (s->hash_size == 0)
        s->hash_size = hash_blob(xs_data(s), strlen(xs_data(s)));
    return s->hash_size;
}

static bool xs_cow_lazy_copy(xs *x, char **data)
{
    if (xs_get_refcnt(x) <= 1)
        return false;

    /* Lazy copy */
    xs_dec_refcnt(x);
    xs_allocate_data(x, x->size, 0);

    if (data) {
        memcpy(xs_data(x), *data, x->size);

        /* Update the newly allocated pointer */
        *data = xs_data(x);
    }
    return true;
}

//interning
xs *xs_concat(xs *string, const xs *prefix, const xs *suffix)
{
    size_t pres = xs_size(prefix), sufs = xs_size(suffix),
           size = xs_size(string), capacity = xs_capacity(string);

    char *pre = xs_data(prefix), *suf = xs_data(suffix),
         *data = xs_data(string);

    xs_cow_lazy_copy(string, &data);

    if (size + pres + sufs <= capacity) {
        memmove(data + pres, data, size);
        memcpy(data, pre, pres);
        memcpy(data + pres + size, suf, sufs + 1);
        if (xs_is_ptr(string)) {
            string->size = size + pres + sufs;
            if (size + pres + sufs < XS_INTERNING_SIZE) {
                return cstr_interning(data, size + pres + sufs, hash_blob(data, size + pres + sufs));
            }
        } else
            string->space_left = 15 - (size + pres + sufs);
    } else {
        xs tmps = xs_literal_empty();
        xs_grow(&tmps, size + pres + sufs);
        char *tmpdata = xs_data(&tmps);
        memcpy(tmpdata + pres, data, size);
        memcpy(tmpdata, pre, pres);
        memcpy(tmpdata + pres + size, suf, sufs + 1);
        xs_free(string);
        *string = tmps;
        string->size = size + pres + sufs;
        if (size + pres + sufs < XS_INTERNING_SIZE) {
             return cstr_interning(data, size + pres + sufs, hash_blob(data, size + pres + sufs));
        }
    }
    return string;
}

//interning
xs *xs_trim(xs *x, const char *trimset)
{
    if (!trimset[0])
        return x;

    char *dataptr = xs_data(x), *orig = dataptr;

    if (xs_cow_lazy_copy(x, &dataptr))
        orig = dataptr;

    /* similar to strspn/strpbrk but it operates on binary data */
    uint8_t mask[32] = {0};

#define check_bit(byte) (mask[(uint8_t) byte / 8] & 1 << (uint8_t) byte % 8)
#define set_bit(byte) (mask[(uint8_t) byte / 8] |= 1 << (uint8_t) byte % 8)
    size_t i, slen = xs_size(x), trimlen = strlen(trimset);

    for (i = 0; i < trimlen; i++)
        set_bit(trimset[i]);
    for (i = 0; i < slen; i++)
        if (!check_bit(dataptr[i]))
            break;
    for (; slen > 0; slen--)
        if (!check_bit(dataptr[slen - 1]))
            break;
    dataptr += i;
    slen -= i;

    /* reserved space as a buffer on the heap.
     * Do not reallocate immediately. Instead, reuse it as possible.
     * Do not shrink to in place if < 16 bytes.
     */
    // memmove is safer than memcpy
    memmove(orig, dataptr, slen);
    /* do not dirty memory unless it is needed */
    if (orig[slen])
        orig[slen] = 0;
    if (xs_is_ptr(x))
        x->size = slen;
    else
        x->space_left = 15 - slen;
    if (slen < XS_INTERNING_SIZE) {
        return cstr_interning(orig, slen, hash_blob(orig, slen));
    }
    return x;
#undef check_bit
#undef set_bit
}
// interning
xs *xs_copy(xs *dest, xs *src){
    /* short string */
    if (!xs_is_ptr(src)){
        dest = xs_free(dest);
        dest->is_large_string = 0;
        dest->is_ptr = 0;
        dest->space_left = src->space_left;
        memcpy(dest->data, src->data, xs_size(src));
        return dest;
    }
    /* large string */
    if (xs_is_large_string(src)){
        dest = xs_free(dest);
        dest->is_large_string = 1;
        dest->is_ptr = 1;
        size_t len = strlen(xs_data(src)) + 1;
        dest->capacity = ilog2(len) + 1;
        dest->size = len - 1;
        dest->ptr = src->ptr;
        xs_inc_refcnt(src);
        return dest;
    } 
    dest = xs_free(dest);
    dest->is_ptr = 1;
    dest->is_large_string = 0;
    size_t len = strlen(xs_data(src)) + 1;
    dest->capacity = ilog2(len) + 1;
    dest->size = len - 1;
    xs_allocate_data(dest, dest->size, 0);
    memcpy(xs_data(dest), xs_data(src), len);
    if (len < XS_INTERNING_SIZE) {
        dest->ptr = cstr_interning(xs_data(src), xs_size(src), hash_blob(xs_data(src), xs_size(src)))->ptr;
    }
    return dest;
}