//
// Created by Omkar Desai on 6/24/21.
//
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <locale.h>
#include <libgen.h>

//#include "blktrace.h"
#include "rbtree.h"
//#include "jhash.h"

static char blkunparse_version[] = "0.1";

FILE *ofp;
static FILE *dump_fp;
static FILE *ip_fp;
static char *dump_binary;
static char *ip_fstr;

FILE * btrace_fp;
char * line = NULL;
size_t len = 0;

#define is_done()	(*(volatile int *)(&done))
static volatile int done;

static struct option l_opts[] = {
        {
                .name = "input",
                .has_arg = required_argument,
                .flag = NULL,
                .val = 'i'
        },
        {
                .name = "version",
                .has_arg = no_argument,
                .flag = NULL,
                .val = 'V'
        },
        {
                .name = NULL,
        }
};

static int name_fixup(char *name)
{
    char *b;

    if (!name)
        return 1;

    b = strstr(name, ".blkparse.");
    if (b)
        *b = '\0';

    return 0;
}

static int do_btrace_file(void){
    // name_fixup();
    //if (ret)
    //    return ret;
    char * log_line;
    size_t len = 0;
    while (getline(&log_line, &len, ip_fp) != -1) {
        printf("%s", log_line);
    }
    return 0;
}

#define S_OPTS  "a:A:b:D:d:f:F:hi:o:Oqstw:vVM"
static char usage_str[] =    "\n\n" \
	"-i <file>           | --input=<file>\n" \
	"-d <file>           | --binary_dump=<file>\n" \
	"[ -V                | --version ]\n\n" \
	"\t-i Input file containing trace data, or '-' for stdin\n" \
	"\t-V Print program version info\n\n";

static void usage(char *prog){

    fprintf(stderr, "Usage: %s %s", prog, usage_str);
}

static void handle_sigint(__attribute__((__unused__)) int sig)
{
    done = 1;
}

int main(int argc, char *argv[]){
    int c, ret;
    char *bin_ofp_buffer = NULL;

    while ((c = getopt_long(argc, argv, S_OPTS, l_opts, NULL)) != -1) {
        switch (c) {
            case 'i':
                ip_fstr = optarg;
                //if (is_pipe(optarg) && !pipeline) {
                    //pipeline = 1;
                    //pipename = strdup(optarg);
                //} else if (resize_devices(optarg) != 0)
                    //return 1;
                break;

            case 'd':
                dump_binary = optarg;
                break;

            case 'V':
                printf("%s version %s\n", argv[0], blkunparse_version);
                return 0;

            default:
                usage(argv[0]);
                return 1;
        }
    }

    signal(SIGINT, handle_sigint);
    signal(SIGHUP, handle_sigint);
    signal(SIGTERM, handle_sigint);

    setlocale(LC_NUMERIC, "en_US");


    if (dump_binary) {
        if (!strcmp(dump_binary, "-"))
            dump_fp = stdout;
        else {
            dump_fp = fopen(dump_binary, "w");
            if (!dump_fp) {
                perror(dump_binary);
                dump_binary = NULL;
                return 1;
            }
        }
        bin_ofp_buffer = malloc(128 * 1024);
        if (setvbuf(dump_fp, bin_ofp_buffer, _IOFBF, 128 * 1024)) {
            perror("setvbuf binary");
            return 1;
        }
    }

    if(ip_fstr){
        ip_fp = fopen(ip_fstr, "r");
        if(!ip_fp){
            perror(ip_fstr);
            ip_fstr = NULL;
            return 1;
        }
    }

    ret = do_btrace_file();

    if (bin_ofp_buffer) {
        fflush(dump_fp);
        free(bin_ofp_buffer);
    }
    return ret;
}