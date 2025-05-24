#ifndef __TREE_H__
#define __TREE_H__

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

// do not change it
#define TEST_SIZE 100000

typedef struct trie_node{
    struct trie_node *chld[4];
    uint32_t mask, port, ip;
    int cmp_len, chld_cnt, matched_len;
    bool terminal;
} trie_node;

extern trie_node root, root_advance;

void create_tree(const char*);
uint32_t *lookup_tree(uint32_t *);
void create_tree_advance(const char*);
uint32_t *lookup_tree_advance(uint32_t *);

uint32_t* read_test_data(const char* lookup_file);

#endif
