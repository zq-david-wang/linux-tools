#include <stdio.h>
#include <stdlib.h>



void *mallocit(int n) {
    return malloc(n);
}
char* process(char *p) {
    int n;
    if (p) free(p);
    scanf("%d", &n); if (n==0) return NULL;
    p = (char *)mallocit(n);
    return p;
}
int main() {
    char *p = NULL;
    int n;
    while(1) {
        p = process(p);
        if (p==NULL) { printf("Fail to malloc\n"); break; }
    }
    return 0;
}
