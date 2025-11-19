#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// /*
// ================================================================================
// _                _  ____  _             _
// | |              | |/ __ \| |           | |
// | |     ___ _   _| | |  | | | ___   __ _| |
// | |    / _ \ | | | | |  | | |/ _ \ / _` | |
// | |___|  __/ |_| | | |__| | | (_) | (_| | |
// |______\___|\__,_|_|\____/|_|\___/ \__,_|_|

// This section contains stubs and simplified re-implementations of Linux kernel
// types, functions, and macros. This allows the target file, which is designed
// for the kernel environment, to be compiled and tested in userspace.
// ================================================================================
// */

/* --- Basic Kernel Types --- */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;

typedef u32 gfp_t;
#define GFP_ATOMIC 0
#define __GFP_ZERO 0 // A flag for memset in kmalloc

/* --- Error Codes (from errno.h) --- */
#define EACCES 13
#define EINVAL 22
#define ENOENT 2
#define EEXIST 17

/* --- Kernel Debugging and Logging Stubs --- */
#define BUG() assert(0)
#define BUG_ON(condition) assert(!(condition))
#define printk(fmt, ...)

/* --- Linked List Implementation --- */
struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

/* --- Spinlock Stubs (for single-threaded tests) --- */
typedef struct {} spinlock_t;
#define spin_lock_bh(lock)      do {} while (0)
#define spin_unlock_bh(lock)    do {} while (0)
#define spin_lock_init(lock)    do {} while (0)

/* --- Memory Allocation Stubs --- */
struct kmem_cache;

// Forward declaration of the internal struct used by the target file
struct cipso_v4_doi_entry {
    struct cipso_v4_doi {
        u32 doi;
        u32 type;
        u8 tags[16];
        struct {
            u8 value;
        } map;
    } def;
    struct list_head list;
};

void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags) {
    void *mem = malloc(sizeof(struct cipso_v4_doi_entry));
    assert(mem != NULL);
    if (flags & __GFP_ZERO) {
        memset(mem, 0, sizeof(struct cipso_v4_doi_entry));
    }
    return mem;
}

void kfree(const void *objp) {
    free((void *)objp);
}

/* --- NetLabel Category Bitmap Stubs --- */
#define NETLBL_CATMAP_MAPSIZE 8 // Allows up to 256 categories for testing
struct netlbl_catmap {
    u32 bitmap[NETLBL_CATMAP_MAPSIZE];
};

int netlbl_catmap_init(struct netlbl_catmap *catmap, gfp_t flags) {
    if (!catmap) return -EINVAL;
    memset(catmap, 0, sizeof(struct netlbl_catmap));
    return 0;
}

void netlbl_catmap_destroy(struct netlbl_catmap *catmap) {
    /* no-op for our static test allocation */
}

int netlbl_catmap_setbit(struct netlbl_catmap *catmap, u32 bit, gfp_t flags) {
    if ((bit / 32) >= NETLBL_CATMAP_MAPSIZE) return -EINVAL;
    catmap->bitmap[bit / 32] |= (1U << (bit % 32));
    return 0;
}

int netlbl_catmap_testbit(const struct netlbl_catmap *catmap, u32 bit) {
    if ((bit / 32) >= NETLBL_CATMAP_MAPSIZE) return 0;
    return (catmap->bitmap[bit / 32] >> (bit % 32)) & 1;
}

/* --- NetLabel Security Attribute Structures --- */
#define NETLBL_SECATTR_MLS_LVL 0x01
#define NETLBL_SECATTR_MLS_CAT 0x02

struct netlbl_lsm_mls {
    u32 lvl;
    struct netlbl_catmap *cat;
};

struct netlbl_lsm_secattr {
    u32 flags;
    struct {
        struct netlbl_lsm_mls mls;
    } attr;
};

/* --- CIPSOv4 Type Definitions (needed by function prototypes) --- */
enum cipso_v4_map_type {
    CIPSO_V4_MAP_PASS = 2,
};
struct cipso_v4_doi;

/*
================================================================================
  _____         _   _____                _
 |_   _|       | | /  __ \              | |
   | | ___  ___| |_| /  \/_ __ ___  __ _| |_ ___
   | |/ _ \/ __| __| |   | '__/ _ \/ _` | __/ _ \
   | |  __/\__ \ |_| \__/\ | |  __/ (_| | ||  __/
   \_/\___||___/\__|\____/_|  \___|\__,_|\__\___|

This section contains the unit tests.
================================================================================
*/

/* --- Prototypes for functions defined in netlabel_cipso_v4.c --- */
int cipso_v4_doi_add(struct cipso_v4_doi *doi_def, gfp_t flags);
int cipso_v4_doi_remove(u32 doi);
int cipso_v4_getattr(const unsigned char *cipso_ptr, struct netlbl_lsm_secattr *secattr);

/* --- Test Helper Functions --- */

/**
 * create_pass_doi - Helper to create a basic DOI definition for testing.
 * @doi_val: The numeric value for the Domain of Interpretation.
 *
 * This DOI definition uses the CIPSO_V4_MAP_PASS type, which means it
 * accepts the levels and categories from the packet without translation. It
 * is configured to accept enumerated tags (type 1) and bitmap tags (type 2).
 */
static struct cipso_v4_doi *create_pass_doi(u32 doi_val) {
    struct cipso_v4_doi *doi = malloc(sizeof(struct cipso_v4_doi));
    assert(doi != NULL);
    memset(doi, 0, sizeof(struct cipso_v4_doi));
    doi->doi = doi_val;
    doi->type = CIPSO_V4_MAP_PASS;
    doi->tags[0] = 1; // CIPSO_TAG_ENUM
    doi->tags[1] = 2; // CIPSO_TAG_BIT
    return doi;
}

/* --- Test Cases --- */

/**
 * test_valid_enumerated_tag - Tests parsing of a valid CIPSO option with a Type 1
 * (enumerated) tag.
 */
static void test_valid_enumerated_tag(void) {
    int ret;
    struct cipso_v4_doi *doi_def = create_pass_doi(3);
    ret = cipso_v4_doi_add(doi_def, GFP_ATOMIC);
    free(doi_def);
    assert(ret == 0);

    // CIPSO option: DOI=3, len=8, tag_type=1, level=10, categories=(none)
    unsigned char cipso_ptr[] = { 3, 8, 1, 0, 10, 0, 0, 0 };
    struct netlbl_lsm_secattr secattr;
    struct netlbl_catmap catmap;
    memset(&secattr, 0, sizeof(secattr));
    netlbl_catmap_init(&catmap, GFP_ATOMIC);
    secattr.attr.mls.cat = &catmap;

    ret = cipso_v4_getattr(cipso_ptr, &secattr);

    assert(ret == 0);
    assert(secattr.flags & NETLBL_SECATTR_MLS_LVL);
    assert(secattr.attr.mls.lvl == 10);
    assert((secattr.flags & NETLBL_SECATTR_MLS_CAT) == 0);

    cipso_v4_doi_remove(3);
}

/**
 * test_unknown_doi - Tests that parsing fails when the CIPSO option specifies a
 * DOI that has not been defined.
 */
static void test_unknown_doi(void) {
    int ret;
    // CIPSO option for a DOI that does not exist (99)
    unsigned char cipso_ptr[] = { 99, 8, 1, 0, 5, 0, 0, 0 };
    struct netlbl_lsm_secattr secattr;
    struct netlbl_catmap catmap;
    memset(&secattr, 0, sizeof(secattr));
    netlbl_catmap_init(&catmap, GFP_ATOMIC);
    secattr.attr.mls.cat = &catmap;

    ret = cipso_v4_getattr(cipso_ptr, &secattr);
    assert(ret == -EACCES);
}

/**
 * test_invalid_option_length - Tests that parsing fails if the length field in
 * the DOI header is shorter than the minimum required for its tag type.
 */
static void test_invalid_option_length(void) {
    int ret;
    struct cipso_v4_doi *doi_def = create_pass_doi(4);
    ret = cipso_v4_doi_add(doi_def, GFP_ATOMIC);
    free(doi_def);
    assert(ret == 0);

    // CIPSO option: DOI=4, len=6 (too short for tag 1 which requires 8), ...
    unsigned char cipso_ptr[] = { 4, 6, 1, 0, 20, 0 };
    struct netlbl_lsm_secattr secattr;
    struct netlbl_catmap catmap;
    memset(&secattr, 0, sizeof(secattr));
    netlbl_catmap_init(&catmap, GFP_ATOMIC);
    secattr.attr.mls.cat = &catmap;

    ret = cipso_v4_getattr(cipso_ptr, &secattr);
    assert(ret == -EINVAL);

    cipso_v4_doi_remove(4);
}

/**
 * test_unsupported_tag_type - Tests that parsing fails if the DOI definition
 * does not explicitly permit the tag type present in the packet.
 */
static void test_unsupported_tag_type(void) {
    int ret;
    // This DOI definition only allows tags 1 and 2.
    struct cipso_v4_doi *doi_def = create_pass_doi(5);
    ret = cipso_v4_doi_add(doi_def, GFP_ATOMIC);
    free(doi_def);
    assert(ret == 0);

    // CIPSO option: DOI=5, len=8, tag_type=5 (not in doi_def->tags[])
    unsigned char cipso_ptr[] = { 5, 8, 5, 0, 30, 0, 0, 0 };
    struct netlbl_lsm_secattr secattr;
    struct netlbl_catmap catmap;
    memset(&secattr, 0, sizeof(secattr));
    netlbl_catmap_init(&catmap, GFP_ATOMIC);
    secattr.attr.mls.cat = &catmap;

    ret = cipso_v4_getattr(cipso_ptr, &secattr);
    assert(ret == -EACCES);

    cipso_v4_doi_remove(5);
}

/**
 * test_valid_bitmap_tag - Tests parsing of a valid CIPSO option with a Type 2
 * (bitmap) tag, ensuring categories are correctly interpreted.
 */
static void test_valid_bitmap_tag(void) {
    int ret;
    struct cipso_v4_doi *doi_def = create_pass_doi(6);
    ret = cipso_v4_doi_add(doi_def, GFP_ATOMIC);
    free(doi_def);
    assert(ret == 0);

    // CIPSO: DOI=6, len=12, tag=2, level=50, cats bitmap=0x05 (bits 0 and 2)
    unsigned char cipso_ptr[] = { 6, 12, 2, 0, 50, 0, 0, 0, 0x05, 0, 0, 0 };
    struct netlbl_lsm_secattr secattr;
    struct netlbl_catmap catmap;
    memset(&secattr, 0, sizeof(secattr));
    netlbl_catmap_init(&catmap, GFP_ATOMIC);
    secattr.attr.mls.cat = &catmap;

    ret = cipso_v4_getattr(cipso_ptr, &secattr);

    assert(ret == 0);
    assert(secattr.flags & NETLBL_SECATTR_MLS_LVL);
    assert(secattr.attr.mls.lvl == 50);
    assert(secattr.flags & NETLBL_SECATTR_MLS_CAT);

    // Categories are 1-based, bits are 0-based.
    // Bitmap 0x05 = 0b0101 -> bits 0 and 2 are set.
    // This corresponds to categories 1 and 3.
    assert(netlbl_catmap_testbit(secattr.attr.mls.cat, 0) == 1); // cat 1
    assert(netlbl_catmap_testbit(secattr.attr.mls.cat, 1) == 0); // cat 2
    assert(netlbl_catmap_testbit(secattr.attr.mls.cat, 2) == 1); // cat 3
    assert(netlbl_catmap_testbit(secattr.attr.mls.cat, 3) == 0); // cat 4

    cipso_v4_doi_remove(6);
}

int main(void) {
    printf("Starting CIPSOv4 unit tests...\n");

    test_valid_enumerated_tag();
    test_unknown_doi();
    test_invalid_option_length();
    test_unsupported_tag_type();
    test_valid_bitmap_tag();

    printf("All tests passed!\n");

    return 0;
}