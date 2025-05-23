#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

trie_node root, root_advance;

// return an array of ip represented by an unsigned integer, size is TEST_SIZE
uint32_t* read_test_data(const char* lookup_file)
{
    uint32_t* ip_vec = (uint32_t*)malloc(sizeof(uint32_t) * TEST_SIZE);
    if(ip_vec == NULL)
    {
        perror("malloc");
        return NULL;
    }
    FILE* fp = fopen(lookup_file, "r");
    char line[32];
    for(int i = 0; i < TEST_SIZE; i++)
    {
        if(fgets(line, sizeof(line), fp) == NULL)
        {
            perror("fgets");
            free(ip_vec);
            fclose(fp);
            return NULL;
        }
        char *dot = strtok(line, ".");
        while(dot != NULL)
        {
            ip_vec[i] = (ip_vec[i] << 8) | (uint8_t)atoi(dot);
            dot = strtok(NULL, ".");
        }
    }
    fclose(fp);
    return ip_vec;
}



void add_trie_node(trie_node *node, uint32_t cur, uint32_t ip, uint32_t mask, uint32_t port)
{
    if(cur > 31)
        return ;
    if (cur == mask)
    {
        *node = (trie_node){.ip = ip, .mask = mask, .port = port, .terminal = true};
        return ;
    }
    int bit = (ip >> (31 - cur)) & 1;
    if(node->chld[bit] == NULL)
    {
        node->chld[bit] = (trie_node *)calloc(sizeof(trie_node), 1);
    }   
    add_trie_node(node->chld[bit], cur + 1, ip, mask, port);
}
// Constructing an advanced trie-tree to lookup according to `forward_file`
void create_tree(const char* forward_file){
    FILE *fp = fopen(forward_file, "r");
    char buf[256];
    while(fgets(buf, sizeof(buf), fp) != NULL)
    {
        char ip_str[32];
        uint32_t mask, port, ip = 0;
        sscanf(buf, "%s %d %d", ip_str, &mask, &port);
        char *dot = strtok(ip_str, ".");
        while(dot != NULL)
        {
            ip = (ip << 8) | (uint8_t)atoi(dot);
            dot = strtok(NULL, ".");
        }
        add_trie_node(&root, 0, ip, mask, port);

    }
}



uint32_t lookup_trie(trie_node *node, uint32_t ip, uint32_t cur)
{
    int bit = (ip >> (31 - cur)) & 1;

    //printf("%x %d %x %d %d %d\n", ip, cur, node->ip, node->mask, node->port, node->terminal);

    if(node->chld[bit] != NULL)
    {
        uint32_t log = lookup_trie(node->chld[bit], ip, cur + 1);
        if(log != -1)
            return log;
    }
    if(cur == node->mask && node->terminal)
    {
        return node->port;
    }
    return -1;
}
void destroy_trie(trie_node *node)
{
    for(int i = 0; i < 26; i ++)
    {
        if(node->chld[i] != NULL)
        {
            destroy_trie(node->chld[i]);
            free(node->chld[i]);
        }
    }
    
}
// Look up the ports of ip in file `lookup_file` using the basic tree
uint32_t *lookup_tree(uint32_t* ip_vec){
    uint32_t *res = (uint32_t *)malloc(sizeof(uint32_t) * TEST_SIZE);
    for(int i = 0; i < TEST_SIZE; i ++)
    {
        
        res[i] = lookup_trie(&root, ip_vec[i], 0);
        //printf("%d\n", res[i]);
    }
    //destroy_trie(&root);
    return res;
}



void add_trie_node_advance(trie_node *node, uint32_t cur, uint32_t ip, uint32_t mask, uint32_t port)
{
    if(cur > 30) 
        return ;
    uint8_t bit[2] = {(ip >> (30 - cur)) & 1, (ip >> (30 - cur)) & 2};
 //   printf("%x %d %x %d %d %d\n", ip, cur, node->ip, mask, node->port, node->terminal);
    if(node->chld[bit[0] + bit[1]] == NULL)
        node->chld[bit[0] + bit[1]] = (trie_node *)calloc(sizeof(trie_node), 1);
        
    if(cur + 2 >= mask)
    {
        if (cur + 2 > mask)
        {
            if(node->chld[!bit[0] + bit[1]] == NULL)
                node->chld[!bit[0] + bit[1]] = (trie_node *)calloc(sizeof(trie_node), 1);
            *node->chld[!bit[0] + bit[1]] = (trie_node){.ip = ip, .mask = mask, .port = port, .terminal = true};
        }
        *node->chld[bit[0] + bit[1]] = (trie_node){.ip = ip, .mask = mask, .port = port, .terminal = true};
        return ;
    }
    add_trie_node_advance(node->chld[bit[0] + bit[1]], cur + 2, ip, mask, port);
}
// Constructing an advanced trie-tree to lookup according to `forwardingtable_filename`
void create_tree_advance(const char* forward_file){
    FILE *fp = fopen(forward_file, "r");
    char buf[256];
    while(fgets(buf, sizeof(buf), fp) != NULL)
    {
        char ip_str[32];
        uint32_t mask, port, ip = 0;
        sscanf(buf, "%s %d %d", ip_str, &mask, &port);
        char *dot = strtok(ip_str, ".");
        while(dot != NULL)
        {
            ip = (ip << 8) | (uint8_t)atoi(dot);
            dot = strtok(NULL, ".");
        }
        add_trie_node_advance(&root_advance, 0, ip, mask, port);
    }
}



uint32_t lookup_trie_advance(trie_node *node, uint32_t ip, uint32_t cur)
{
    if(cur > 30)
        return -1;
    int bit = (ip >> (30 - cur)) & 3;

    //printf("%x %d %x %d %d %d\n", ip, cur, node->ip, node->mask, node->port, node->terminal);

    if(node->chld[bit] != NULL)
    {
        uint32_t log = lookup_trie_advance(node->chld[bit], ip, cur + 2);
        if(log != -1)
            return log;
    }
    if(cur >= node->mask && node->terminal)
    {
        return node->port;
    }
    return -1;
}
// Look up the ports of ip in file `lookup_file` using the advanced tree
uint32_t *lookup_tree_advance(uint32_t* ip_vec){
    uint32_t *res = (uint32_t *)malloc(sizeof(uint32_t) * TEST_SIZE);
    for(int i = 0; i < TEST_SIZE; i ++)
    {
        res[i] = lookup_trie_advance(&root_advance, ip_vec[i], 0);

    }
    return res;
}