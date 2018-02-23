#ifndef QEMU_THREAD_POSIX_H
#define QEMU_THREAD_POSIX_H

#include <pthread.h>
#include <semaphore.h>

typedef QemuMutex QemuRecMutex;
#define qemu_rec_mutex_destroy      qemu_mutex_destroy
#define qemu_rec_mutex_lock_impl    qemu_mutex_lock_impl
#define qemu_rec_mutex_trylock_impl qemu_mutex_trylock_impl
#define qemu_rec_mutex_unlock_impl  qemu_mutex_unlock_impl

struct QemuMutex {
    pthread_mutex_t lock;
    bool initialized;
};

struct QemuCond {
    pthread_cond_t cond;
    bool initialized;
};

struct QemuSemaphore {
#ifndef CONFIG_SEM_TIMEDWAIT
    pthread_mutex_t lock;
    pthread_cond_t cond;
    unsigned int count;
#else
    sem_t sem;
#endif
    bool initialized;
};

struct QemuEvent {
#ifndef __linux__
    pthread_mutex_t lock;
    pthread_cond_t cond;
#endif
    unsigned value;
    bool initialized;
};

struct QemuThread {
    pthread_t thread;
};

#endif
