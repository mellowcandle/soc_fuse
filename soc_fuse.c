/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/
#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <sys/queue.h>

#define MAX_REG_NAME 64
#define MAX_NAME_SPACE_NAME 64

struct props {
	unsigned int size : 2;
	unsigned int write : 1;
	unsigned int read : 1;
};

struct reg {
	char name[MAX_REG_NAME];
	struct props props;
};

struct name_space {
	char name[MAX_NAME_SPACE_NAME];
	SLIST_ENTRY(reg) regs;
};

struct soc {
	SLIST_ENTRY(name_space) spaces;
};

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
        const char *filename;
        int show_help;
} options;
#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
        OPTION("--soc_file=%s", filename),
        OPTION("-h", show_help),
        OPTION("--help", show_help),
        FUSE_OPT_END
};
static void *hello_init(struct fuse_conn_info *conn,
                        struct fuse_config *cfg)
{
        (void) conn;

        return NULL;
}
static int hello_getattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi)
{
        (void) fi;

        int res = 0;
        return res;
}
static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags)
{
        return 0;
}
static int hello_open(const char *path, struct fuse_file_info *fi)
{
        return 0;
}
static int hello_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
	return 0;
}
static struct fuse_operations hello_oper = {
        .init           = hello_init,
        .getattr        = hello_getattr,
        .readdir        = hello_readdir,
        .open           = hello_open,
        .read           = hello_read,
};
static void show_help(const char *progname)
{
        printf("usage: %s [options] <mountpoint>\n\n", progname);
        printf("File-system specific options:\n"
               "    --soc_file=<s>      Name of the \"soc\" file\n"
               "\n");
}
int main(int argc, char *argv[])
{
        int ret;
        struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
        /* Set defaults -- we have to use strdup so that
           fuse_opt_parse can free the defaults if other
           values are specified */
        /* Parse options */
        if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
                return 1;

        /* When --help is specified, first print our own file-system
           specific help text, then signal fuse_main to show
           additional help (by adding `--help` to the options again)
           without usage: line (by setting argv[0] to the empty
           string) */
        if (options.show_help) {
                show_help(argv[0]);
                assert(fuse_opt_add_arg(&args, "--help") == 0);
                args.argv[0][0] = '\0';
        } else if (!options.filename) {
		printf("Error: --soc_file argument is mandatory\n");
		show_help(argv[0]);
		return 1;
	}

        ret = fuse_main(args.argc, args.argv, &hello_oper, NULL);
        fuse_opt_free_args(&args);
        return ret;
}
