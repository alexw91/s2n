/*
 * Self-test file for the no-uninit-locals check.
 *
 * This file exercises every corner case the check must handle correctly.
 * The companion .expected.json file lists exactly which lines should produce
 * findings. If libclang changes AST representation across versions, this
 * self-test will detect the divergence before the real scan runs.
 */
#include <stdint.h>
#include <string.h>

/* Simulates s2n's DEFER_CLEANUP macro */
#define TEST_DEFER_CLEANUP(_thealloc, _thecleanup) \
    __attribute__((cleanup(_thecleanup))) _thealloc

struct test_blob {
    uint8_t *data;
    uint32_t size;
};

static void test_blob_free(struct test_blob *b) { (void)b; }

/* --- Cases that SHOULD produce findings (uninitialized) --- */

void case_struct_uninit(void) {
    struct test_blob blob;           /* line 28: FINDING */
    (void)blob;
}

void case_scalar_uninit(void) {
    int x;                           /* line 33: FINDING */
    (void)x;
}

void case_pointer_uninit(void) {
    char *ptr;                       /* line 38: FINDING */
    (void)ptr;
}

void case_uint8_uninit(void) {
    uint8_t byte_val;                /* line 43: FINDING */
    (void)byte_val;
}

void case_macro_expanded_uninit(void) {
    TEST_DEFER_CLEANUP(struct test_blob blob_uninit, test_blob_free);  /* line 48: FINDING */
    (void)blob_uninit;
}

void case_nested_block_uninit(void) {
    if (1) {
        int nested;                  /* line 53: FINDING */
        (void)nested;
    }
}

/* --- Cases that should NOT produce findings (initialized) --- */

void case_struct_init(void) {
    struct test_blob blob = { 0 };
    (void)blob;
}

void case_scalar_init(void) {
    int x = 0;
    (void)x;
}

void case_pointer_init(void) {
    char *ptr = NULL;
    (void)ptr;
}

void case_macro_expanded_init(void) {
    TEST_DEFER_CLEANUP(struct test_blob blob_init = { 0 }, test_blob_free);
    (void)blob_init;
}

void case_for_loop_init(void) {
    for (int i = 0; i < 10; i++) {
        (void)i;
    }
}

void case_function_call_init(void) {
    size_t len = strlen("hello");
    (void)len;
}

/* --- Edge cases that should NOT produce findings --- */

/* Function parameters are PARM_DECL, not VAR_DECL */
void case_parameters(int a, const char *b, uint32_t c) {
    (void)a; (void)b; (void)c;
}

/* Global variables are not local (semantic_parent is not FUNCTION_DECL) */
static int global_uninit;
