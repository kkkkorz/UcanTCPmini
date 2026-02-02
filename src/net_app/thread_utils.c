#include "thread_utils.h"
#include <stdlib.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>

typedef struct {
    thread_func_t func;
    void *arg;
} thread_start_t;

static DWORD WINAPI thread_start_win(LPVOID p)
{
    thread_start_t *ts = (thread_start_t *)p;
    if (ts && ts->func)
        ts->func(ts->arg);
    free(ts);
    return 0;
}

int thread_create(thread_func_t func, void *arg)
{
    thread_start_t *ts = (thread_start_t *)malloc(sizeof(thread_start_t));
    if (!ts)
        return -1;
    ts->func = func;
    ts->arg = arg;
    HANDLE h = CreateThread(NULL, 0, thread_start_win, ts, 0, NULL);
    if (!h) {
        free(ts);
        return -1;
    }
    CloseHandle(h);
    return 0;
}

void thread_sleep(unsigned seconds)
{
    Sleep((DWORD)(seconds * 1000));
}

#else

#include <pthread.h>
#include <unistd.h>

int thread_create(thread_func_t func, void *arg)
{
    pthread_t t;
    int r = pthread_create(&t, NULL, func, arg);
    if (r == 0) {
        pthread_detach(t);
        return 0;
    }
    return -1;
}

void thread_sleep(unsigned seconds)
{
    sleep(seconds);
}

#endif
