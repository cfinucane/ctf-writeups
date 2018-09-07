/* To build: gcc -o dec_wrapper dec_wrapper.c -ldl */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <link.h>

#define TARGET_FUNCTION_OFFSET 0xbe7

int main() {
  void *lib = dlopen("./dec_dec_dec-c55c231bfbf686ab058bac2a56ce6cc49ae32fe086af499571e335c9f7417e5b", RTLD_LAZY);

  if (lib == NULL) {
    printf("Failed to load binary: %s\n", dlerror());
    exit(-1);
  }

  struct link_map *lm;
  dlinfo(lib, RTLD_DI_LINKMAP, &lm);
  printf("Loaded binary at: %p\n", (void *)lm->l_addr);

  char* (*f)(char*) = (char* (*)(char*))(lm->l_addr + TARGET_FUNCTION_OFFSET);
  printf("Function is at: %p\n", f);

  char input[10];
  while(fgets(input, 10, stdin)) {
    input[strcspn(input, "\n")] = 0; // strip newline from input
    char* res = f(input); // call target function
    printf("%s\n", res);
  }

  dlclose(lib);
}
