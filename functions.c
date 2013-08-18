/**
 * @file functions.c
 * @author Mohammad Reza Hosseini 
 * 
 * some usefull functions
 * 
 * 
 * 
 * 
 * 
 */

#include "functions.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

int array_max(int* array, int size){
	int max = INT32_MIN;
	int i = 0;
	for (i = 0; i < size; i++){
		if (array[i] > max)
			max = array[i];
	}
	return max;
}