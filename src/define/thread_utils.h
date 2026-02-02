#ifndef THREAD_UTILS_H
#define THREAD_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(*thread_func_t)(void *);

int thread_create(thread_func_t func, void *arg);
void thread_sleep(unsigned seconds);

#ifdef __cplusplus
}
#endif

#endif // THREAD_UTILS_H
