/**
 * @file    dbuffer.c
 * @author  Srimanta Barua <srimanta.barua1@gmail.com>
 * @date    18 October 2020
 * @version 0.1
 * @brief   Split off logic for synchronized data buffer before appending to string
 */

/**
 * @brief Waitqueue for threads waiting to write data
 */
static DECLARE_WAIT_QUEUE_HEAD(BPERF_WQ);

/**
 * @brief Static buffer before writing to string buffer
 */
#define SNPRINTF_BUFSZ 4096
static char SNPRINTF_BUFFER[SNPRINTF_BUFSZ];
static int SNPRINTF_WRITTEN = 0;

/**
 * @brief Write formatted data to static staging buffer
 */
static void bperf_snprintf(const char *fmt, ...) {
	va_list args;
	int ret = 0;
	while (true) {
		va_start(args, fmt);
		ret = vsnprintf(SNPRINTF_BUFFER + SNPRINTF_WRITTEN, SNPRINTF_BUFSZ - SNPRINTF_WRITTEN, fmt, args);
		if (ret + SNPRINTF_WRITTEN >= SNPRINTF_BUFSZ) {
			ret = bperf_sbuffer_write(&SBUFFER, SNPRINTF_BUFFER, SNPRINTF_WRITTEN);
			SNPRINTF_WRITTEN -= ret;
			if (SNPRINTF_WRITTEN > 0) {
				memcpy(SNPRINTF_BUFFER, SNPRINTF_BUFFER + ret, SNPRINTF_WRITTEN);
			}
			va_end(args);
		} else {
			SNPRINTF_WRITTEN += ret;
			va_end(args);
			break;
		}
	}
}

/**
 * @brief Flush staged string to buffer
 */
static void bperf_snprintf_flush(void) {
	int ret;
	while (SNPRINTF_WRITTEN > 0) {
		ret = bperf_sbuffer_write(&SBUFFER, SNPRINTF_BUFFER, SNPRINTF_WRITTEN);
		SNPRINTF_WRITTEN -= ret;
		if (SNPRINTF_WRITTEN > 0) {
			memcpy(SNPRINTF_BUFFER, SNPRINTF_BUFFER + ret, SNPRINTF_WRITTEN);
		}
	}
}

/**
 * @brief A data node for a single thread
 */
struct bperf_dbuffer_thread {
	uint64_t perfevtsel_bak[BPERF_MAX_PMC]; /* Back up perfevtsel registers */
	uint64_t fixed_ctrl_bak;                /* Back up fixed ctrl register */
	uint64_t global_ctrl_bak;               /* Back up perf global ctrl register */
	uint64_t timestamp;                     /* Timestamp in nanoseconds */
	uint64_t last_pmc[BPERF_MAX_PMC];       /* Last PMCx reading */
	uint64_t last_fixed[BPERF_MAX_FIXED];   /* Last fixed counter reading */
	uint64_t pmc[BPERF_MAX_PMC];            /* PMCx increment */
	uint64_t fixed[BPERF_MAX_FIXED];        /* fixed counter increment */
	bool     has_pmc[BPERF_MAX_PMC];        /* Whether data for this PMCx is present */
	bool     has_fixed[BPERF_MAX_FIXED];    /* Whether data for this fixed counter is present */
};

/**
 * @brief A variable-sized data node for a single timestamp
 */
struct bperf_dbuffer {
	size_t                      num_threads; /* Number of threads */
	atomic_t                    to_check_in; /* Number of threads to check in */
	bool                        *checked_in; /* Whether the given thread has checked in its data */
	struct bperf_dbuffer_thread *data;       /* Per-thread data */
} DBUFFER = { 0 };

/**
 * @brief Initialize buffer
 */
static int bperf_dbuffer_init(struct bperf_dbuffer *db, size_t nthreads) {
	db->data = kvmalloc(nthreads * sizeof(struct bperf_dbuffer_thread), GFP_KERNEL);
	if (!db->data || IS_ERR(db->data)) {
		printk(KERN_ALERT "bperf: Failed to initialize data buffer: kvmalloc failed\n");
		return -ENOMEM;
	}
	db->checked_in = kvmalloc(nthreads * sizeof(bool), GFP_KERNEL);
	if (!db->checked_in || IS_ERR(db->checked_in)) {
		kvfree(db->data);
		printk(KERN_ALERT "bperf: Failed to initialize checked_in array: kvmalloc failed\n");
		return -ENOMEM;
	}
	memset(db->checked_in, 0, nthreads * sizeof(bool));
	db->num_threads = nthreads;
	atomic_set(&db->to_check_in, db->num_threads);
	return 0;
}

/**
 * @brief Free memory for buffer
 */
static void bperf_dbuffer_fini(struct bperf_dbuffer *dbuffer) {
	kvfree(dbuffer->data);
}

/**
 * @brief Write measured data to string buffer
 */
static void bperf_dbuffer_to_string(struct bperf_dbuffer *dbuffer, size_t thread_id) {
	size_t i;
	uint64_t timestamp = dbuffer->data[thread_id].timestamp;

	bperf_snprintf("timestamp: %llu\n", timestamp);

#define write_x(X) do { \
	bperf_snprintf(#X ": ");\
	for (i = 0; i < dbuffer->num_threads; i++) { \
		if (!dbuffer->data[i].has_ ## X) { \
			continue; \
		} \
		bperf_snprintf("%llu ", dbuffer->data[i].X); \
	} \
	bperf_snprintf("\n"); \
} while (0)

	// FIXME: Align with BPERF_MAX_FIXED and BPERF_MAX_PMC
	write_x(pmc[0]);
	write_x(pmc[1]);
	write_x(pmc[2]);
	write_x(pmc[3]);
	write_x(fixed[0]);
	write_x(fixed[1]);
	write_x(fixed[2]);
	write_x(fixed[3]);

	bperf_snprintf_flush();
}

/**
 * @brief Notify that thread has finished writing data, and block if required
 */
static void bperf_dbuffer_thread_checkin(struct bperf_dbuffer *dbuffer, size_t thread_id) {
	if (thread_id >= dbuffer->num_threads) {
		printk(KERN_ALERT "bperf: Invalid thread id: %lu: max: %lu\n", thread_id, dbuffer->num_threads);
		return;
	}
	printk(KERN_INFO "bperf: Thread %lu check-in start\n", thread_id);
	wait_event_interruptible(BPERF_WQ, kthread_should_stop() || !dbuffer->checked_in[thread_id]);
	if (kthread_should_stop()) {
		return;
	}
	printk(KERN_INFO "bperf: Thread %lu check-in done: checked_in: %d: atomic: %u\n", thread_id, dbuffer->checked_in[thread_id], atomic_read(&dbuffer->to_check_in));
	dbuffer->checked_in[thread_id] = true;

	if (atomic_dec_and_test(&dbuffer->to_check_in)) {
		printk(KERN_INFO "bperf: Thread %lu writing to sbuffer\n", thread_id);
		bperf_dbuffer_to_string(dbuffer, thread_id);
		atomic_set(&dbuffer->to_check_in, dbuffer->num_threads);
		memset(dbuffer->checked_in, 0, dbuffer->num_threads * sizeof(bool));
		wake_up_interruptible(&BPERF_WQ);
	}
}
