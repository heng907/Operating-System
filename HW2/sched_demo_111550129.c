#define _GNU_SOURCE
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sched.h>
#include <time.h>
#include <errno.h>

pthread_barrier_t barrier;

typedef struct {
    int thread_num;          // Thread index: 0..n-1
    int policy;              // SCHED_NORMAL or SCHED_FIFO
    int priority;            // NORMAL -> -1 ; FIFO -> 1..99
    double busy_time;        // Busy-wait duration (seconds)
} thread_info_t;

/* Busy-wait that counts only the thread's CPU time */
static void busy_for_cpu_time(double seconds) {
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    double start = ts.tv_sec + ts.tv_nsec / 1e9;
    while(1){
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
        double now = ts.tv_sec + ts.tv_nsec / 1e9;
        if (now - start >= seconds) break;
        asm volatile("" ::: "memory");
    }
}

void *thread_func(void *arg)
{
    /* 1. Wait until all threads are ready */
    pthread_barrier_wait(&barrier);
    thread_info_t *info = (thread_info_t*)arg;

    /* 2. Perform the task */
    for (int i = 0; i < 3; i++) {
        printf("Thread %d is running\n", info->thread_num);
        fflush(stdout);
        busy_for_cpu_time(info->busy_time);   // Busy for <time_wait> seconds
    }
    /* 3. Exit the thread function */
    return NULL;
}

int main(int argc, char *argv[])
{
    /* 1. Parse program arguments */
    int num_threads = -1;
    double busy_time = -1.0;
    char *str_policy = NULL;   // e.g., "NORMAL,FIFO,..."
    char *str_priority = NULL; // e.g., "-1,10,..."

    int opt;
    while ((opt = getopt(argc, argv, "n:t:s:p:")) != -1) {
        switch (opt) {
            case 'n': 
                num_threads = atoi(optarg); 
                break;
            case 't': 
                busy_time = atof(optarg); 
                break;
            case 's': 
                str_policy  = optarg; 
                break;
            case 'p': 
                str_priority= optarg; 
                break;
            default:
                fprintf(stderr, "Usage: %s -n <num_threads> -t <busy_sec> -s <NORMAL|FIFO,...> -p <-1|prio,...>\n", argv[0]);
                return 1;
        }
    }

    // ---- Parse -s / -p into arrays ----
    int *policies = calloc(num_threads, sizeof(int));   // SCHED_NORMAL / SCHED_FIFO
    int *priorities = calloc(num_threads, sizeof(int));   // -1 or 1..99

    // Parse priority
    char *savep = NULL;
    char *tok = strtok_r(str_priority, ",", &savep);
    for (int i = 0; i < num_threads; i++) {
        priorities[i] = (int)strtol(tok, NULL, 10);
        tok = strtok_r(NULL, ",", &savep);
    }

    // Parse policy
    char *saves = NULL;
    tok = strtok_r(str_policy, ",", &saves);
    for (int i = 0; i < num_threads; i++) {
        policies[i] = (strcmp(tok, "FIFO") == 0) ? SCHED_FIFO : SCHED_OTHER; // SCHED_OTHER is SCHED_NORMAL
        tok = strtok_r(NULL, ",", &saves);
    }

    /* 2. Create <num_threads> worker threads */
    pthread_t *threads = calloc(num_threads, sizeof(pthread_t));
    pthread_attr_t *thread_attrs = calloc(num_threads, sizeof(pthread_attr_t));
    thread_info_t *thread_infos = calloc(num_threads, sizeof(thread_info_t));

    /* 3. Set CPU affinity */
    // bind main and all threads to CPU 0
    cpu_set_t set; 
    CPU_ZERO(&set); 
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);

    // Initialize barrier: all worker threads + main thread (n+1 total)
    pthread_barrier_init(&barrier, NULL, num_threads + 1);

    // Create each thread: explicitly set policy/priority/affinity
    for (int i = 0; i < num_threads; i++) {
        /* 4. Set attributes for each thread */
        thread_infos[i].thread_num = i;
        thread_infos[i].policy = policies[i];
        thread_infos[i].priority = priorities[i];
        thread_infos[i].busy_time = busy_time;

        pthread_attr_init(&thread_attrs[i]);
        pthread_attr_setaffinity_np(&thread_attrs[i], sizeof(set), &set);
        pthread_attr_setinheritsched(&thread_attrs[i], PTHREAD_EXPLICIT_SCHED);
        pthread_attr_setschedpolicy(&thread_attrs[i], thread_infos[i].policy);

        struct sched_param sp = {0};
        sp.sched_priority = (thread_infos[i].policy == SCHED_FIFO) ? thread_infos[i].priority : 0;
        pthread_attr_setschedparam(&thread_attrs[i], &sp);

        pthread_create(&threads[i], &thread_attrs[i], thread_func, &thread_infos[i]);
    }

    /* 5. Start all threads at once */
    pthread_barrier_wait(&barrier);

    /* 6. Wait for all threads to finish */
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        pthread_attr_destroy(&thread_attrs[i]);
    }

    pthread_barrier_destroy(&barrier);
    free(thread_infos); 
    free(thread_attrs); 
    free(threads);
    free(policies); 
    free(priorities);
    return 0;
}
