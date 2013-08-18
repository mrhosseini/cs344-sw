/**
 * @file ll.c
 * @author Mohammad Reza Hosseini 
 * 
 */
#include "ll.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

node_t* node_create(void) {
	node_t* n = (node_t*) malloc(sizeof(node_t));
	bzero(n, sizeof(node_t));
	return n;
}

void node_push_back(node_t* head, node_t* n) {
	node_t* cur = head;
	while (cur->next != NULL) {
		cur = cur->next;
	}
	cur->next = n;
	n->prev = cur;
}

void node_remove(node_t** head, node_t* n) {
	
	/* list has only one element */
	if (n->next == NULL && n->prev == NULL) {
		*head = NULL;
		free(n->data);
		free(n);
		return;
	}
	
	/* remove first element of the list */
	if (n->prev == NULL) {
		*head = n->next;
		(*head)->prev = NULL;
		
		free(n->data);
		free(n);
		return;
	}
	
	/* remove last element of the list */
	if (n->next == NULL){
		n->prev->next = NULL;
		
		free(n->data);
		free(n);
		return;
	}
	
	/* remove an enterior element */
	n->prev->next = n->next;
	n->next->prev = n->prev;
	
	free(n->data);
	free(n);
}

int node_length(node_t* head) {
	int len = 0;
	node_t *walker = head;
	
	while (walker){
		len++;
		walker = walker->next;
	}
	
	return len;
}
