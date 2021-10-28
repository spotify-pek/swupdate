/*
 * (C) Spotify Copyright 2020
 *
 * SPDX-License-Identifier:     BSD
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "handler.h"
#include "swupdate.h"
#include "util.h"
#include "progress.h"
#include "bsdqueue.h"


/* XDelta is using autoconf/autoheader to generate certain defines. 
 * It has to be included prior to xdelta header. If you know a better way
 * of carying over generated config.h over from the other package - let me know.
 */
#include <xdelta/config.h>
#include <xdelta/xdelta3.h>


#define DEFAULT_GETBLK_SIZE (1U << 20) /* 1MB */
#define DEFAULT_INPUT_WINDOW_SIZE (1U << 19) /* 512 Kb. Smaller window would lead to the less memory usage but more fseeks */
#define DEFAULT_LRU_SIZE (32)
#define DEFAULT_BLOCK_SIZE (DEFAULT_GETBLK_SIZE / DEFAULT_LRU_SIZE)

/* Helper macro that moves last element of the queue to front */
#define TAILQ_PROMOTE(head, elm, field) do { TAILQ_REMOVE(head, elm, field); \
                                             TAILQ_INSERT_HEAD(head, elm, field); \
                                        } while(0)

typedef struct img_type img_type;

typedef TAILQ_HEAD(head_s, node) head_t;

/* LRU cache for source blocks */
typedef struct node {
    xoff_t blockno;
    size_t size;
    uint8_t* block;
    TAILQ_ENTRY(node) nodes;
} node_t;

typedef struct handler_data {
    char* src_filename;
    char* dst_filename;
    char* patch_filename;
    FILE* src_file;
    FILE* dst_file;
    FILE* patch_file;
    uint8_t* patch_buf; /* contains segments of patch file data */
    size_t patch_buf_sz; /* size of the patch segment buffer */
    size_t expected_dst_size; /* used for progress reporting */
    size_t src_size;
    head_t head; /* LRU cache */
} handler_data;


// Forward declarations
void xdelta_handler_init(void);
int xdelta_handler(struct img_type *img, void __attribute__ ((__unused__)) *data);

// xdelta callback functions
static void
main_free(void __attribute__ ((__unused__)) *opaque, void *ptr) { free (ptr); }

static void*
main_alloc(void __attribute__ ((__unused__)) *opaque, size_t  items, usize_t  size) {
  void *r = malloc(items * size);
  if (r == NULL) {
      ERROR("Memory allocation failed. Requested bytes %u items %u item size %u", items * size, items, size);
  }
  return r;
}

/* XDelta is often request the same blocks of source data
 * due to the nature of how VCDIFF patch is constructed. This
 * results in substantial amount of fseek calls for the same 
 * source file segment. We are using simple LRU cache to
 * minimize disk io when possible. This speeds up patch
 * application on 1GB system partion more than twice
*/
static int
init_block_cache(head_t* head) {
    TAILQ_INIT(head);

    for (int i = 0; i < DEFAULT_LRU_SIZE; i++) {
        node_t* e = malloc(sizeof(node_t));
        if (e == NULL) {
            ERROR("cache malloc failed size %d", sizeof(node_t));
            return -1;
        }
        memset(e, 0, sizeof(node_t));
        if ((e->block = malloc(DEFAULT_BLOCK_SIZE)) == NULL) {
            ERROR("cache malloc failed size %d", DEFAULT_BLOCK_SIZE);
            return -1;
        }
        e->blockno = (xoff_t) -1;
        e->size = DEFAULT_BLOCK_SIZE;
        TAILQ_INSERT_TAIL(head, e, nodes);
        e = NULL;
    }
    return 0;
}

/* Main LRU cache access function.
 * On cache hit, accessed element moves to the front of the queue.
 * On cache miss, tail element (least recently used) is replaced
 * with a new block of data from the soruce file and moved to front.
 * When this happens, allocated memory region of last element is reused
 * to avoid unnecessary free/malloc.
 */
static node_t*
get_block(handler_data* handle, xd3_source* source) {
    head_t* head = &handle->head;
    xoff_t offset = source->blksize * source->getblkno;
    node_t *e = NULL, *next = NULL;
    
    /* check cache */
    TAILQ_FOREACH_SAFE(e, head, nodes, next) {
        if (e->blockno == source->getblkno) {
            TAILQ_PROMOTE(head, e, nodes);
            return e;
        }
    }
    /* cache miss, read from file */
    e = TAILQ_LAST(head, head_s);
    TAILQ_PROMOTE(head, e, nodes);

    if (fseek(handle->src_file, offset, SEEK_SET) != 0) {
        ERROR("fseek failed for source file %s position %llu error %s",
                handle->src_filename, offset, strerror(errno));
        return NULL;
    }
    e->size = fread((void*)e->block, sizeof(e->block[0]), source->blksize, handle->src_file);
    if(ferror(handle->src_file)) {
        ERROR("fread on source file %s failed %s", handle->src_filename, strerror(errno));
        return NULL;
    }
    e->blockno = source->getblkno;
    return e;
}

static void
free_block_cache(head_t* head) {
    node_t* e = NULL;
    while (head && !TAILQ_EMPTY(head)) {
        e = TAILQ_FIRST(head);
        TAILQ_REMOVE(head, e, nodes);
        if (e->block) { free(e->block); }
        free(e);
        e = NULL;
    }
}

// Helpers
static void 
set_default_xd3_config(xd3_config* config, xd3_source* source) {
    xd3_init_config(config, 0);
    config->winsize = DEFAULT_INPUT_WINDOW_SIZE;
    config->sprevsz = XD3_DEFAULT_SPREVSZ;
    config->iopt_size = XD3_DEFAULT_IOPT_SIZE;

    // callbacks
    config->alloc = main_alloc;
    config->freef = main_free;
    config->getblk = NULL; /* We use XD3_GETSRCBLK instead */

    // source defaults
    source->blksize = DEFAULT_BLOCK_SIZE;
    source->onblk = DEFAULT_BLOCK_SIZE;
    source->onlastblk = DEFAULT_BLOCK_SIZE;
    source->max_blkno = DEFAULT_LRU_SIZE - 1;
    source->max_winsize = DEFAULT_GETBLK_SIZE;
    source->curblk = malloc(source->blksize);
    source->curblkno = (xoff_t) -1;
}

static size_t
get_file_size(char* path) {
    uint64_t size = 0;
    struct stat sbuf = {0};
    int fd;

    if((fd = open(path, O_RDONLY)) >= 0) {
        if(fstat(fd, &sbuf) == 0) {
            if (S_ISREG(sbuf.st_mode)) {
                size = sbuf.st_size;
            } else if (S_ISBLK(sbuf.st_mode)) {
                ioctl(fd, BLKGETSIZE64, &size);
            };
        }
        close(fd);
        return size;
    }

    ERROR("Failed to obtain file size of %s error %s", path, strerror(errno));
    return 0;
}

static int
read_sw_description_extras(img_type *img, handler_data* handle) {
    char* dst_file_sz_str = NULL;

    // source file name aka "old file" name
    if ((handle->src_filename = dict_get_value(&img->properties, "xdeltasrc")) == NULL) {
        ERROR("Property xdeltasrc is missing in sw-description");
        return -1;
    }
    handle->src_size = get_file_size(handle->src_filename);
    if ((dst_file_sz_str = dict_get_value(&img->properties, "dst_size")) != NULL) {
        handle->expected_dst_size = strtoul(dst_file_sz_str, NULL, 10);
    } else {
        handle->expected_dst_size = handle->src_size; /* some approximation */
    }

    return 0;
}

static int
open_files(img_type *img, handler_data* handle) {
    if (!(handle->src_file = fopen(handle->src_filename, "rb"))) {
        ERROR("Failed to open source file %s error %s", handle->src_filename, strerror(errno));
        return errno;
    }
    if (!(handle->dst_file = fopen(handle->dst_filename, "wb"))) {
        ERROR("Failed to open destination file %s error %s", handle->dst_filename, strerror(errno));
        return errno;
    }
    // TODO: activate streaming feature in swupdate to minimize mem usage
    if (!(handle->patch_file = fdopen(img->fdin, "rb"))) { // swupdate gives us FD of the patch
        ERROR("Failed to open patch file fd %d name %s error %s", img->fdin, handle->patch_filename, strerror(errno));
        return errno;
    }
    return 0;
}

static int
read_from_patch_file(handler_data* handle, xd3_stream* stream) {
    // Read patch file data
    size_t patch_bytes_read = fread(handle->patch_buf, sizeof(handle->patch_buf[0]), handle->patch_buf_sz, handle->patch_file);
    if (ferror(handle->patch_file)) {
        ERROR("fread on patch file %s failed %s", handle->patch_filename, strerror(errno));
        return errno;
    }

    // set flush flag if EOF has reached
    if (patch_bytes_read < handle->patch_buf_sz) {
        INFO("Input EOF!")
        xd3_set_flags(stream, XD3_FLUSH | stream->flags);
    }

    xd3_avail_input(stream, handle->patch_buf, patch_bytes_read);
    return 0;
}

static int
feed_src_block(handler_data* handle, xd3_source* source) {
    node_t* e = get_block(handle, source);
    if (e) {
        source->onblk = e->size;
        source->curblk = e->block;
        source->curblkno = e->blockno;
        return 0;
    }
    return -1;
}

static int
write_to_output_file(handler_data* handle, xd3_stream* stream) {
    size_t dst_bytes_written = fwrite(stream->next_out, sizeof(stream->next_out[0]), stream->avail_out, handle->dst_file);
    if (dst_bytes_written != (size_t)stream->avail_out) {
        ERROR("Failed to write %u bytes to output file %s error %s",
                stream->avail_out, handle->dst_filename, strerror(errno));
        return errno;
    }
    xd3_consume_output(stream);
    return 0;
}

static void
report_update_progress(handler_data* handle, xd3_stream* stream) {
    static unsigned int prev_perc = 0; /* ! static */
    if (handle->expected_dst_size != 0) {
        unsigned int perc = ((float)(stream->total_out) / handle->expected_dst_size) * 100;
        perc = max(perc, 0);
        perc = min(perc, 100);
        if (perc != prev_perc) {
            swupdate_progress_update(perc);
            prev_perc = perc;
            INFO("Patch progress %d%% bytes written %llu expected %u", perc, stream->total_out, handle->expected_dst_size);
        }
    }
}

// Implementation
int xdelta_handler(img_type *img, void __attribute__ ((__unused__)) *data)
{
    int xd3ret, ret = 0;
    xd3_stream stream;
    xd3_config config;
    xd3_source source;
    handler_data handle;

    memset(&handle, 0, sizeof(handle));
    memset(&stream, 0, sizeof(stream));
    memset(&source, 0, sizeof(source));
    memset(&config, 0, sizeof(config));

    // Parse the extra sw-description fields
    handle.dst_filename = img->device;
    handle.patch_filename = img->fname;
    if ((ret = read_sw_description_extras(img, &handle)) != 0) {
        goto cleanup;
    }
    INFO("Starting XDelta diff from %s to %s with %s", handle.src_filename, handle.dst_filename, handle.patch_filename);

    // Initialize block cache
    if((ret = init_block_cache(&handle.head)) != 0) {
        goto cleanup;
    }

    // Open all relevant files
    if ((ret = open_files(img, &handle)) != 0) {
        goto cleanup;
    }

    // Xdelta3 setup
    set_default_xd3_config(&config, &source);
    if ((ret = xd3_config_stream(&stream, &config) != 0)) {
        ERROR("xd3_config_stream failed %d", ret);
        goto cleanup;
    }
    if (handle.src_size) { // if we know source size, tell it to the xdelta
        ret = xd3_set_source_and_size(&stream, &source, handle.src_size);
    } else {
        ret = xd3_set_source(&stream, &source);
    }
    if (ret != 0) {
        ERROR("xd3_set_source failed %d", ret);
        goto cleanup;
    }

    // prepare patch buffer
    handle.patch_buf_sz = config.winsize;
    if (!(handle.patch_buf = (void*) malloc(handle.patch_buf_sz))) {
        ERROR("Patch buffer malloc failed sz %d", handle.patch_buf_sz);
        ret = -1;
        goto cleanup;
    }

    /* Main processing loop modeled after 
     * https://github.com/jmacd/xdelta/blob/wiki/ProgrammingGuide.md#inputoutput-loop
     */
    do {
        // Read patch file data
        if ((ret = read_from_patch_file(&handle, &stream)) != 0) {
            goto cleanup;
        }

process:
        /* this command does all the magic */
        xd3ret = xd3_decode_input(&stream);
        switch (xd3ret) {
            case XD3_INPUT: /* stream requires more input */            
                INFO("process: XD3_INPUT");
                continue;

            case XD3_OUTPUT: /* destimation ( aka "new" ) file segment is ready to be written */
            {
                INFO("process: XD3_OUTPUT");
                if ((ret = write_to_output_file(&handle, &stream)) != 0) {
                    goto cleanup;
                }
                report_update_progress(&handle, &stream);
                goto process;
            }

            case XD3_GETSRCBLK: /* need data from the source file */
            {
                INFO("process: XD3_GETSRCBLK");
                if ((ret = feed_src_block(&handle, &source)) != 0) {
                    goto cleanup;
                }
                goto process;
            }

            case XD3_GOTHEADER:
                INFO("process: XD3_GOTHEADER");
                goto process;
            case XD3_WINSTART:
                INFO("process: XD3_WINSTART");
                goto process;
            case XD3_WINFINISH:
                INFO("process: XD3_WINFINISH");
                goto process;

            default:
                ERROR("Unexpected error code from XDelta %s %d", stream.msg, xd3ret);
                ret = xd3ret;  
                goto cleanup;
        }
    } while (!(stream.flags & XD3_FLUSH));

cleanup:
    if (ret != 0) {
        ERROR("XDelta3 have failed us! %d %s", ret, strerror(errno));
    } else {
        INFO("XDelta3 patch is DONE! wrote %llu to %s ret %d", stream.total_out, handle.dst_filename, ret);
    }

    if (handle.src_file) { fclose(handle.src_file); }
    if (handle.dst_file) { fclose(handle.dst_file); }
    if (handle.patch_file) { fclose(handle.patch_file); }
    if (handle.patch_buf) { free(handle.patch_buf); }
    xd3_close_stream(&stream);
    xd3_free_stream(&stream);
    free_block_cache(&handle.head);
    return ret;
}

__attribute__((constructor))
void xdelta_handler_init(void)
{
    register_handler("xdelta_image", xdelta_handler, IMAGE_HANDLER, NULL);
}
