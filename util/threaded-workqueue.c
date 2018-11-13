/*
 * Lockless and Efficient Threaded Workqueue Abstraction
 *
 * Author:
 *   Xiao Guangrong <xiaoguangrong@tencent.com>
 *
 * Copyright(C) 2018 Tencent Corporation.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/bitmap.h"
#include "qemu/threaded-workqueue.h"

#define SMP_CACHE_BYTES 64
#define BITS_ALIGNED_TO_CACHE(_bits_)   \
    QEMU_ALIGN_UP(_bits_, SMP_CACHE_BYTES * BITS_PER_BYTE)

/*
 * the request representation which contains the internally used mete data,
 * it is the header of user-defined data.
 *
 * It should be aligned to the nature size of CPU.
 */
struct ThreadRequest {
    /*
     * the request has been handled by the thread and need the user
     * to fetch result out.
     */
    bool done;
    bool inited;
    int th_idx;
};
typedef struct ThreadRequest ThreadRequest;

struct ThreadLocal {
    struct Threads *threads;

    /*
     * the interim bitmap used by the thread to avoid frequent
     * memory allocation
     */
    unsigned long *result_bitmap;

    void *requests;

    /*
     * the bit in these two bitmaps indicates the index of the requests
     * respectively. If it's the same, the corresponding request is free
     * and owned by the user, i.e, where the user fills a request. Otherwise,
     * it is valid and owned by the thread, i.e, where the thread fetches
     * the request and write the result.
     */

    /* after the user fills the request, the bit is flipped. */
    unsigned long *request_bm;
    /* after handles the request, the thread flips the bit. */
    unsigned long *done_bm;

    QemuThread thread;

    /* thread is useless and needs to exit */
    bool quit;

    /* the event used to wake up the thread */
    struct {
        QemuEvent ev;
    } QEMU_ALIGNED(SMP_CACHE_BYTES);

    struct {
        QemuEvent completion_ev;
    } QEMU_ALIGNED(SMP_CACHE_BYTES);
} QEMU_ALIGNED(SMP_CACHE_BYTES);
typedef struct ThreadLocal ThreadLocal;

/*
 * the main data struct represents multithreads which is shared by
 * all threads
 */
struct Threads {

    /*
     * the interim bitmap used by the user to avoid frequent
     * memory allocation
     */
    unsigned long *result_bitmap;

    /* the request header, ThreadRequest, is contained */
    unsigned int request_size;

    /* the number of requests that each thread need handle */
    unsigned int thread_request_nr;

    unsigned int threads_nr;

    /* the request is pushed to the thread with round-robin manner */
    unsigned int current_thread_index;

    ThreadedWorkqueueOps *ops;
    ThreadLocal *per_thread_data;
};
typedef struct Threads Threads;

static inline ThreadRequest *choose_req(Threads *threads, ThreadLocal *th, int idx)
{
    void *req = th->requests;

    return req + idx * threads->request_size;
}

static int request_to_index(Threads *threads, ThreadRequest *req)
{
    void *addr0 = threads->per_thread_data[req->th_idx].requests;
    void *addr = req;
    return (addr - addr0) / threads->request_size;
}

/*
 * free request: the request is not used by any thread, however, it might
 *   contian the result need the user to call thread_request_done()
 *
 * valid request: the request contains the request data and it's commited
 *   to the thread, i,e. it's owned by thread.
 */
static unsigned long *get_free_request_bitmap(Threads *threads, int th_idx)
{
    ThreadLocal *th = &threads->per_thread_data[th_idx];

    bitmap_xor(threads->result_bitmap, th->request_bm, th->done_bm,
               threads->thread_request_nr);

    /*
     * paired with smp_wmb() in mark_request_free() to make sure that we
     * read request_done_bitmap before fetch the result out.
     */
    smp_rmb();

    return threads->result_bitmap;
}

static ThreadRequest *find_free_request(Threads *threads)
{
    int i;

    for (i = 0; i < threads->threads_nr; i++) {
        int j = (threads->current_thread_index + i) % threads->threads_nr;
        unsigned long *bm = get_free_request_bitmap(threads, j);
        int index = find_next_zero_bit(bm, threads->thread_request_nr, 0);

        if (index < threads->thread_request_nr) {
            return choose_req(threads, &threads->per_thread_data[j], index);
        }
    }
    return NULL;
}

static void mark_request_valid(ThreadLocal *th, int request_index)
{
    /*
     * paired with smp_rmb() in find_first_valid_request_index() to make
     * sure the request has been filled before the bit is flipped that
     * will make the request be visible to the thread
     */
    smp_wmb();

    change_bit(request_index, th->request_bm);
}

static int thread_find_first_valid_request_index(ThreadLocal *thread)
{
    Threads *threads = thread->threads;
    int index;

    bitmap_xor(thread->result_bitmap, thread->request_bm,
               thread->done_bm, threads->thread_request_nr);
    /*
     * paired with smp_wmb() in mark_request_valid() to make sure that
     * we read request_fill_bitmap before fetch the request out.
     */
    smp_rmb();

    index = find_next_bit(thread->result_bitmap, threads->thread_request_nr, 0);
    return index < threads->thread_request_nr ? index : -1;
}

static void mark_request_free(ThreadLocal *thread, ThreadRequest *request)
{
    int index = request_to_index(thread->threads, request);

    /*
     * smp_wmb() is implied in change_bit_atomic() that is paired with
     * smp_rmb() in get_free_request_bitmap() to make sure the result
     * has been saved before the bit is flipped.
     */
    change_bit_atomic(index, thread->done_bm);
}

/* retry to see if there is available request before actually go to wait. */
#define BUSY_WAIT_COUNT 1000

static ThreadRequest *thread_busy_wait_for_request(ThreadLocal *thread)
{
    int index, count = 0;

    for (count = 0; count < BUSY_WAIT_COUNT; count++) {
        index = thread_find_first_valid_request_index(thread);
        if (index >= 0) {
            return choose_req(thread->threads, thread, index);
        }

        cpu_relax();
    }

    return NULL;
}

static void *thread_run(void *opaque)
{
    ThreadLocal *self_data = (ThreadLocal *)opaque;
    Threads *threads = self_data->threads;
    void (*handler)(void *request) = threads->ops->thread_request_handler;
    ThreadRequest *request;

    while (!atomic_read(&self_data->quit)) {
        qemu_event_reset(&self_data->ev);

        request = thread_busy_wait_for_request(self_data);
        if (!request) {
            qemu_event_wait(&self_data->ev);
            continue;
        }

        assert(!request->done);

        handler(request + 1);
        request->done = true;
        mark_request_free(self_data, request);
        qemu_event_set(&self_data->completion_ev);
    }

    return NULL;
}

static void uninit_requests(Threads *threads)
{
    int i, j;

    for (i = 0; i < threads->threads_nr; i++) {
        ThreadLocal *th = &threads->per_thread_data[i];

        for (j = 0; j < threads->thread_request_nr; j++) {
            ThreadRequest *req = choose_req(threads, th, j);

            if (!req->inited) {
                /* reqs are inited in order, so it's safe to stop here */
                goto reqs_done;
            }
            threads->ops->thread_request_uninit(req + 1);
        }
    }

 reqs_done:
    for (i = 0; i < threads->threads_nr; i++) {
        ThreadLocal *th = &threads->per_thread_data[i];

        qemu_vfree(th->request_bm);
        qemu_vfree(th->done_bm);
        qemu_vfree(th->requests);
    }

    g_free(threads->result_bitmap);
}

static void th_reqs_init(Threads *threads, int th_idx)
{
    ThreadLocal *th = &threads->per_thread_data[th_idx];
    size_t n = threads->thread_request_nr;
    /* fill up the cache line to prevent false sharing */
    size_t n_full = BITS_ALIGNED_TO_CACHE(n);

    th->request_bm = bitmap_new_aligned(n_full, SMP_CACHE_BYTES);
    th->done_bm = bitmap_new_aligned(n_full, SMP_CACHE_BYTES);

    th->requests = qemu_memalign(SMP_CACHE_BYTES, n * threads->request_size);
    memset(th->requests, 0, n * threads->request_size);
}

static int init_requests(Threads *threads)
{
    int ret;
    int i, j;

    threads->result_bitmap = bitmap_new(threads->thread_request_nr);
    QEMU_BUILD_BUG_ON(!QEMU_IS_ALIGNED(sizeof(ThreadRequest), sizeof(long)));

    threads->request_size = threads->ops->thread_get_request_size();
    threads->request_size = QEMU_ALIGN_UP(threads->request_size, sizeof(long));
    threads->request_size += sizeof(ThreadRequest);

    for (i = 0; i < threads->threads_nr; i++) {
        th_reqs_init(threads, i);
    }

    for (i = 0; i < threads->threads_nr; i++) {
        ThreadLocal *th = &threads->per_thread_data[i];

        for (j = 0; j < threads->thread_request_nr; j++) {
            ThreadRequest *req = choose_req(threads, th, j);

            ret = threads->ops->thread_request_init(req + 1);
            if (ret) {
                goto exit;
            }
            req->th_idx = i;
            req->inited = true;
        }
    }

    return 0;

exit:
    uninit_requests(threads);
    return ret;
}

static void uninit_thread_data(Threads *threads)
{
    ThreadLocal *thread_local = threads->per_thread_data;
    int i;

    for (i = 0; i < threads->threads_nr; i++) {
        atomic_set(&thread_local[i].quit, true);
        qemu_event_set(&thread_local[i].ev);
        qemu_thread_join(&thread_local[i].thread);
        qemu_event_destroy(&thread_local[i].ev);
        qemu_event_destroy(&thread_local[i].completion_ev);
        g_free(thread_local[i].result_bitmap);
    }
}

static void init_thread_data(Threads *threads, const char *th_name)
{
    ThreadLocal *thread_local = threads->per_thread_data;
    char *name;
    int i;

    for (i = 0; i < threads->threads_nr; i++) {
        thread_local[i].threads = threads;

        thread_local[i].result_bitmap = bitmap_new(threads->thread_request_nr);

        qemu_event_init(&thread_local[i].ev, false);
        qemu_event_init(&thread_local[i].completion_ev, false);

        name = g_strdup_printf("%s/%d", th_name, i);
        qemu_thread_create(&thread_local[i].thread, name,
                           thread_run, &thread_local[i], QEMU_THREAD_JOINABLE);
        g_free(name);
    }
}

Threads *threaded_workqueue_create(const char *name, unsigned int threads_nr,
                               int thread_request_nr, ThreadedWorkqueueOps *ops)
{
    size_t th_size;
    Threads *threads;

    threads = g_new0(Threads, 1);
    threads->ops = ops;

    threads->threads_nr = threads_nr;
    threads->thread_request_nr = thread_request_nr;

    th_size = sizeof(ThreadLocal) * threads->threads_nr;
    threads->per_thread_data = qemu_memalign(SMP_CACHE_BYTES, th_size);
    memset(threads->per_thread_data, 0, th_size);

    if (init_requests(threads) < 0) {
        qemu_vfree(threads->per_thread_data);
        g_free(threads);
        return NULL;
    }

    init_thread_data(threads, name);
    return threads;
}

void threaded_workqueue_destroy(Threads *threads)
{
    uninit_thread_data(threads);
    uninit_requests(threads);
    qemu_vfree(threads->per_thread_data);
    g_free(threads);
}

static void request_done(Threads *threads, ThreadRequest *request)
{
    if (!request->done) {
        return;
    }

    threads->ops->thread_request_done(request + 1);
    request->done = false;
}

void *threaded_workqueue_get_request(Threads *threads)
{
    ThreadRequest *request;

    request = find_free_request(threads);
    if (request == NULL) {
        return NULL;
    }

    request_done(threads, request);
    return request + 1;
}

void threaded_workqueue_submit_request(Threads *threads, void *request)
{
    ThreadRequest *req = request - sizeof(ThreadRequest);
    int request_index = request_to_index(threads, req);
    ThreadLocal *thread_local = &threads->per_thread_data[req->th_idx];

    assert(!req->done);

    mark_request_valid(&threads->per_thread_data[req->th_idx], request_index);

    threads->current_thread_index = req->th_idx;
    qemu_event_set(&thread_local->ev);
}

void threaded_workqueue_wait_for_requests(Threads *threads)
{
    int i, j;

 retry:
    for (i = 0; i < threads->threads_nr; i++) {
        ThreadLocal *th = &threads->per_thread_data[i];
        unsigned long *bm;

        qemu_event_reset(&th->completion_ev);
        bm = get_free_request_bitmap(threads, i);
        for (j = 0; j < threads->thread_request_nr; j++) {
            if (test_bit(j, bm)) {
                qemu_event_wait(&th->completion_ev);
                goto retry;
            }
            request_done(threads, choose_req(threads, th, j));
        }
    }
}
