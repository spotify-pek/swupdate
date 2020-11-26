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


// Proto declaration
void xdeltacmd_handler_init(void);
int run_cmd_with_output(const char* cmd);

int run_cmd_with_output(const char* cmd) {
	FILE *fp;
	char data[1024];

	/* Open the command for reading. */
	fp = popen(cmd, "r");
	if (fp == NULL) {
		ERROR("Failed to run command %s", cmd);
		return -1;
	}

	/* Read the output a line at a time - output it. */
	while (fgets(data, sizeof(data), fp) != NULL) {
		INFO("%s", data);
	}

	/* close */
	return pclose(fp);
}

// Implementations
static int xdeltacmd_handler(struct img_type *img, void __attribute__ ((__unused__)) *data)
{
	int ret = 0;
	char *src_filename = NULL;
	char cmd[1024] = {0};

	// source file name aka "old file" name
	src_filename = dict_get_value(&img->properties, "xdeltasrc");
	if (src_filename == NULL) {
		ERROR("Property 'bsdiffsrc' is missing in sw-description.");
		return -1;
	}

	snprintf(cmd, 1023, "xdelta3 -vv -f -d -B 524288 -s %s /tmp/%s %s", src_filename, img->fname, img->device);
	/* run the command */
	ret = run_cmd_with_output(cmd);

	if (ret != 0) {
		ERROR("xdelta3 have failed us! %d %s", ret, strerror(errno));
	}

	return ret;
}

__attribute__((constructor))
void xdeltacmd_handler_init(void)
{
	register_handler("xdeltacmd_image", xdeltacmd_handler, IMAGE_HANDLER, NULL);
}
