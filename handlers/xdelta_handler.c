/*
 * (C) Duck the Copyright 2020
 * Janitor at spotify
 *
 * SPDX-License-Identifier:     BSD
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "handler.h"
#include "swupdate.h"
#include "util.h"


/* XDelta is using autoconf/autoheader to generate certain defines. 
   It has to be included prior to xdelta header. If you know a better way
   of carying over generated config.h over from the other package - let me know.
*/
#include <xdelta/config.h>
#include <xdelta/xdelta3.h>


#define DEFAULT_GETBLK_SIZE (1U << 20) /* 1MB */
#define DEFAULT_INPUT_WINDOW_SIZE (1U << 19) /* 512 Kb. Smaller window would lead to the less memory usage but more fseeks */

typedef struct img_type img_type;

// Forward declarations
void xdelta_handler_init(void);
int xdelta_handler(struct img_type *img, void __attribute__ ((__unused__)) *data);

// Helpers
typedef struct handler_data {
    char* src_filename;
    char* dst_filename;
    char* patch_filename;
    FILE* src_file;
    FILE* dst_file;
	FILE* patch_file;
    uint8_t* patch_buf;
    size_t patch_buf_sz;
} handler_data;

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
    source->blksize = DEFAULT_GETBLK_SIZE;
    source->curblk = malloc(source->blksize);
    source->curblkno = (xoff_t) -1;
}

static int
read_sw_description_extras(img_type *img, handler_data* handle) {
    // source file name aka "old file" name
    if ((handle->src_filename = dict_get_value(&img->properties, "xdeltasrc")) == NULL) {
        ERROR("Property xdeltasrc is missing in sw-description");
        return -1;
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
        xd3_set_flags(stream, XD3_FLUSH | stream->flags);
    }

    xd3_avail_input(stream, handle->patch_buf, patch_bytes_read);
    return 0;
}

static int
read_from_src_file(handler_data* handle, xd3_source* source) {
    int ret;
    xoff_t offset = source->blksize * source->getblkno;

    if ((ret = fseek(handle->src_file, offset, SEEK_SET)) != 0) {
        ERROR("fseek failed for source file %s position %llu error %s",
                handle->src_filename, offset, strerror(errno));
        return errno;
    }
    source->onblk = fread((void*)source->curblk, sizeof(source->curblk[0]), source->blksize, handle->src_file);
    if(ferror(handle->src_file)) {
        ERROR("fread on source file %s failed %s", handle->src_filename, strerror(errno));
        return errno;
    }
    source->curblkno = source->getblkno;
    return 0;
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
    if ((ret = xd3_set_source(&stream, &source) != 0)) {
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

    // main processing loop
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
                continue;

            case XD3_OUTPUT: /* destimation ( aka "new" ) file segment is ready to be written */
            {
                if ((ret = write_to_output_file(&handle, &stream)) != 0) {
                    goto cleanup;
                }
                goto process;
            }

            case XD3_GETSRCBLK: /* need data from the source file */
            {
                if ((ret = read_from_src_file(&handle, &source)) != 0) {
                    goto cleanup;
                }
                goto process;
            }

            case XD3_GOTHEADER:
            case XD3_WINSTART:
            case XD3_WINFINISH:
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

    if (handle.patch_buf) { free(handle.patch_buf); }
    if (source.curblk) { free((void*)source.curblk); }
    if (handle.src_file) { fclose(handle.src_file); }
    if (handle.dst_file) { fclose(handle.dst_file); }
    if (handle.patch_file) { fclose(handle.patch_file); }
    xd3_close_stream(&stream);
    xd3_free_stream(&stream);

	return ret;
}

__attribute__((constructor))
void xdelta_handler_init(void)
{
    register_handler("xdelta_image", xdelta_handler, IMAGE_HANDLER, NULL);
}
