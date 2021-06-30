//
// Created by Omkar Desai on 6/24/21.
//
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
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

#include "blktrace.h"
#include "rbtree.h"
//#include "jhash.h"

static char blkunparse_version[] = "0.1";

struct per_dev_info {
    dev_t dev;
    char *name;

    int backwards;
    unsigned long long events;
    unsigned long long first_reported_time;
    unsigned long long last_reported_time;
    unsigned long long last_read_time;
    struct io_stats io_stats;
    unsigned long skips;
    unsigned long long seq_skips;
    unsigned int max_depth[2];
    unsigned int cur_depth[2];

    struct rb_root rb_track;

    int nfiles;
    int ncpus;

    unsigned long *cpu_map;
    unsigned int cpu_map_max;

    struct per_cpu_info *cpus;
};

/*
 * some duplicated effort here, we can unify this hash and the ppi hash later
 */
struct process_pid_map {
    pid_t pid;
    char comm[16];
    struct process_pid_map *hash_next, *list_next;
};

#define PPM_HASH_SHIFT	(8)
#define PPM_HASH_SIZE	(1 << PPM_HASH_SHIFT)
#define PPM_HASH_MASK	(PPM_HASH_SIZE - 1)
static struct process_pid_map *ppm_hash_table[PPM_HASH_SIZE];

struct per_process_info {
    struct process_pid_map *ppm;
    struct io_stats io_stats;
    struct per_process_info *hash_next, *list_next;
    int more_than_one;

    /*
     * individual io stats
     */
    unsigned long long longest_allocation_wait[2];
    unsigned long long longest_dispatch_wait[2];
    unsigned long long longest_completion_wait[2];
};

#define PPI_HASH_SHIFT	(8)
#define PPI_HASH_SIZE	(1 << PPI_HASH_SHIFT)
#define PPI_HASH_MASK	(PPI_HASH_SIZE - 1)
static struct per_process_info *ppi_hash_table[PPI_HASH_SIZE];
static struct per_process_info *ppi_list;
static int ppi_list_entries;

//just copied over form blkparse. may need changes


static int ndevices = 0; //static config for now.
static struct per_dev_info *devices; //how to fill this list of devices?

static char *input_dir;

//static FILE *dump_fp;
static FILE *ip_fp;
static char *dump_binary_dir;
static char *ip_fstr;

FILE * btrace_fp;
char * line = NULL;
size_t len = 0;

#define is_done()	(*(volatile int *)(&done))
static volatile int done;

static int resize_devices(char *name)
{
    int size = (ndevices + 1) * sizeof(struct per_dev_info);

    devices = realloc(devices, size);
    if (!devices) {
        fprintf(stderr, "Out of memory, device %s (%d)\n", name, size);
        return 1;
    }
    memset(&devices[ndevices], 0, sizeof(struct per_dev_info));
    devices[ndevices].name = name;
    ndevices++;
    return 0;
}

static struct per_dev_info *get_dev_info(dev_t dev)
{
    struct per_dev_info *pdi;
    int i;

    for (i = 0; i < ndevices; i++) {
        if (!devices[i].dev)
            devices[i].dev = dev;
        if (devices[i].dev == dev)
            return &devices[i];
    }

    if (resize_devices(NULL))
        return NULL;

    pdi = &devices[ndevices - 1];
    pdi->dev = dev;
    pdi->first_reported_time = 0;
    pdi->last_read_time = 0;

    return pdi;
}

static void resize_cpu_info(struct per_dev_info *pdi, int cpu)
{
    struct per_cpu_info *cpus = pdi->cpus;
    int ncpus = pdi->ncpus;
    int new_count = cpu + 1;
    int new_space, size;
    char *new_start;

    size = new_count * sizeof(struct per_cpu_info);
    cpus = realloc(cpus, size);
    if (!cpus) {
        char name[20];
        //fprintf(stderr, "Out of memory, CPU info for device %s (%d)\n",
        //        get_dev_name(pdi, name, sizeof(name)), size);
        fprintf(stderr, "Out of memory");
        exit(1);
    }

    new_start = (char *)cpus + (ncpus * sizeof(struct per_cpu_info));
    new_space = (new_count - ncpus) * sizeof(struct per_cpu_info);
    memset(new_start, 0, new_space);

    pdi->ncpus = new_count;
    pdi->cpus = cpus;

    for (new_count = 0; new_count < pdi->ncpus; new_count++) {
        struct per_cpu_info *pci = &pdi->cpus[new_count];

        if (!pci->fd) {
            pci->fd = -1;
            memset(&pci->rb_last, 0, sizeof(pci->rb_last));
            pci->rb_last_entries = 0;
            pci->last_sequence = -1;
        }
    }
}


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

static struct per_cpu_info *get_cpu_info(struct per_dev_info *pdi, int cpu){
    struct per_cpu_info *pci;

    if (cpu >= pdi->ncpus)
        resize_cpu_info(pdi, cpu);

    pci = &pdi->cpus[cpu];
    pci->cpu = cpu;
    return pci;
}

/*
static struct ms_stream *ms_alloc(struct per_dev_info *pdi, int cpu)
{
    struct ms_stream *msp = malloc(sizeof(*msp));

    msp->next = NULL;
    msp->first = msp->last = NULL;
    msp->pdi = pdi;
    msp->cpu = cpu;

    if (ms_prime(msp))
        ms_sort(msp);

    return msp;
}
*/
/*
static int setup_out_file(struct per_dev_info *pdi, int cpu){
    printf("setup_out_file function stub\n");
    char *dname, *p;
    struct per_cpu_info *pci = get_cpu_info(pdi, cpu);
    return 0;
}
 */

static int setup_out_file(struct per_dev_info *pdi, int cpu){
    int len = 0;
    char *dname, *p;
    struct stat st;
    struct per_cpu_info *pci = get_cpu_info(pdi, cpu);

    pci->cpu = cpu;
    pci->fdblock = -1;

    p = strdup(pdi->name);
    dname = dirname(p);

    if (strcmp(dname, ".")) {
        input_dir = dname;
        p = strdup(pdi->name);
        strcpy(pdi->name, basename(p));
    }
    free(p);

    if (input_dir)
        len = sprintf(pci->fname, "%s/", input_dir);

    snprintf(pci->fname + len, sizeof(pci->fname)-1-len,
             "%s.blktrace.%d", pdi->name, pci->cpu);

    //if (stat(pci->fname, &st) < 0)
    //    return 0;
    //if (!st.st_size)
    //    return 1;

    pci->fd = open(pci->fname, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (pci->fd < 0) {
        perror(pci->fname);
        return 0;
    }

    printf("Output file %s added\n", pci->fname);

    //cpu_mark_online(pdi, pci->cpu);

    pdi->nfiles++;
    //ms_alloc(pdi, pci->cpu);

    return 1;

}
/*
static int do_btrace_file(void){
    // name_fixup();
    //if (ret)
    //    return ret;
    int i, cpu;
    struct per_dev_info *pdi;
    for (i = 0; i< ndevices; i++){
        pdi = &devices[i];
        for(cpu = 0; setup_out_file(pdi, cpu); cpu++);
    }
    char * log_line;
    size_t len = 0;
    while (getline(&log_line, &len, ip_fp) != -1) {
        printf("%s", log_line);
    }
    return 0;
}
*/
#define S_OPTS  "a:A:b:D:d:f:F:hi:o:Oqstw:vVM"
static char usage_str[] =    "\n\n" \
	"-i <file>           | --input=<file>\n" \
	"-d <dir_path>       | --binary_dump=<dir_path>\n" \
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

static int setup_out_files(void){
    int i, cpu;
    struct per_dev_info *pdi;

    for (i = 0; i < ndevices; i++) {
        pdi = &devices[i];
        int num_cpus = get_nprocs();

        for (cpu = 0; cpu < num_cpus; cpu++)
            setup_out_file(pdi, cpu);
    }
    return 1;
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
                dump_binary_dir = optarg;
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

/*
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
*/
    if(ip_fstr){
        printf("%s\n", ip_fstr);
        ip_fp = fopen(ip_fstr, "r");
        if(!ip_fp){
            perror(ip_fstr);
            ip_fstr = NULL;
            return 1;
        }
    }

    resize_devices(ip_fstr);

    ret = setup_out_files();
    if (!ret){
        perror("output file creation error\n");
        return ret;
    }
    //ret = do_btrace_file();

    //if (bin_ofp_buffer) {
    //    fflush(dump_fp);
    //    free(bin_ofp_buffer);
    //}
    printf("%d\n", ret);
    return ret;
}