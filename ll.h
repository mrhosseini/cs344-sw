/**
 * @file ll.h
 * @author Mohammad Reza Hosseini 
 * 
 * 
 */
#ifndef LL_H_
#define LL_H_

typedef struct node {
	struct node* prev;
	struct node* next;
	void* data;
} node_t;


node_t* node_create(void);

void node_push_back(node_t* head, node_t* n);

void node_remove(node_t** head, node_t* n);

int node_length(node_t* head);
#endif
