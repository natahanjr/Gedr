#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable(char *input) {
    char buffer[64];
    char name[128];

    strcpy(buffer, input);
    sprintf(name, "Hello %s", input);
    gets(buffer);
    system(input);
}

void memory_issue(int *arr, int n) {
    int *copy = malloc(n * sizeof(int));
    memcpy(copy, arr, sizeof(copy));
    free(copy);
}
