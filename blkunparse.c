//
// Created by Omkar Desai on 6/24/21.
//
/*
Each blocktrace record contains the following fields

[Device Major Number,Device Minor Number] [CPU Core ID] [Record ID] [Timestamp (in nanoseconds)]
[ProcessID] [Trace Action] [OperationType] [SectorNumber + I/O Size] [ProcessName]
*/
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
#include <time.h>

#include "blktrace.h"
#include "rbtree.h"
#include "blktrace_api.h"
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

struct ms_stream {
    struct ms_stream *next;
    struct trace *first, *last;
    struct per_dev_info *pdi;
    unsigned int cpu;
};

#define MS_HASH(d, c) ((MAJOR(d) & 0xff) ^ (MINOR(d) & 0xff) ^ (cpu & 0xff))

struct ms_stream *ms_head;
struct ms_stream *ms_hash[256];

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

static struct rb_root rb_sort_root;
static unsigned long rb_sort_entries;

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

unsigned long unparse_genesis_time;

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

static struct ms_stream *ms_alloc(struct per_dev_info *pdi, int cpu)
{
    struct ms_stream *msp = malloc(sizeof(*msp));

    msp->next = NULL;
    msp->first = msp->last = NULL;
    msp->pdi = pdi;
    msp->cpu = cpu;

    //if (ms_prime(msp))
    //    ms_sort(msp);

    return msp;
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

static int setup_out_file(struct per_dev_info *pdi, int cpu){
    int len = 0;
    char *dname, *p;
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

    pci->fd = open(pci->fname, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (pci->fd < 0) {
        perror(pci->fname);
        return 0;
    }

    printf("Output file %s added\n", pci->fname);

    //cpu_mark_online(pdi, pci->cpu);

    pdi->nfiles++;
    ms_alloc(pdi, pci->cpu);

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

void process_q(struct blk_io_trace* bio_, char* tok[]){
    bio_->sector = *tok[7];
    bio_->bytes = *tok[9];
}

void get_action_code(struct blk_io_trace* bio_, char* tok[]){
    char act = *tok[5];
    if (act == *"Q") {
        //printf("case Q");
        bio_->action = __BLK_TA_QUEUE;
        process_q(bio_, tok);
        //break;
    }
    else if(act == *"I") {
        //printf("case I");
        bio_->action = __BLK_TA_INSERT;
        //break;
    }
    else if(act == *"M") {
        //printf("case M");
        bio_->action = __BLK_TA_BACKMERGE;
        //break;
    }
    else if(act == *"F") {
        //printf("case F");
        bio_->action = __BLK_TA_FRONTMERGE;
        //break;
    }
    else if(act == *"G") {
        //printf("case G");
        bio_->action = __BLK_TA_GETRQ;
        //break;
    }
    else if(act == *"S") {
        //printf("case S");
        bio_->action = __BLK_TA_SLEEPRQ;
        //break;
    }
    else if (act == *"R") {
        //printf("case R");
        bio_->action = __BLK_TA_REQUEUE;
        //break;
    }
    else if(act == *"D") {
        //this is probably the one
        //printf("case D");
        bio_->action = __BLK_TA_ISSUE;
        //break;
    }
    else if(act == *"C") {
        //printf("case C");
        bio_->action = __BLK_TA_COMPLETE;
        //break;
    }
    else if(act == *"P") {
        //printf("case P");
        bio_->action = __BLK_TA_PLUG;
        //break;
    }
    else if(act == *"U") {
        //printf("case U");
        bio_->action = __BLK_TA_UNPLUG_IO;
        //break;
    }
    else if(act == *"UT") {
        //printf("case UT");
        bio_->action = __BLK_TA_UNPLUG_TIMER;
        //break;
    }
    else if(act == *"X") {
        //printf("case X");
        bio_->action = __BLK_TA_SPLIT;
        //break;
    }
    else if(act == *"B") {
        //printf("case B");
        bio_->action = __BLK_TA_BOUNCE;
        //break;
    }
    else if(act == *"A") {
        //printf("case A");
        bio_->action = __BLK_TA_REMAP;
        //break;
    }
    else{
        fprintf(stderr, "Bad fs action %c\n", act);
        //break;
    }
}

struct blk_io_trace get_bit(char * tok[]){
    struct blk_io_trace bio_;

    bio_.sequence = (__u32) *tok[2];
    bio_.time = (__u64)unparse_genesis_time+ *tok[3];
    bio_.cpu = (__u32) *tok[1];
    bio_.pid = (__u32) *tok[4];
    __u16 error_status = 0;
    bio_.error = error_status;
    bio_.device = 0; //fix this
    //pdi_ = &devices[0];
    get_action_code(&bio_, tok);
    return bio_;
}

static int handle(void){
    ssize_t read;
    char * t;
    char *delim = " ";
    char *token;
    while((read = getline(&line, &len, ip_fp)) != -1){
        t = line;
        char *tokens[20];
        int i=0;
        struct per_dev_info * device_ptr;
        struct per_cpu_info * cpu_ptr;

        token = strtok(t, delim);
        while(token != NULL) {
            tokens[i] = token;
            i++;
            token = strtok(NULL, delim);
        }
        struct blk_io_trace processed_bit = get_bit(tokens);
        device_ptr = &devices[0];
        cpu_ptr = get_cpu_info(device_ptr, processed_bit.cpu);
        //FILE * fp_tmp;
        //if ((fp_tmp = fopen("/tmp/blkunparse/test1", "ab"))==NULL){
        //    printf("Error! opening file");
        //    return 1;
        //}

        //char* test_str = "Omkar is stupid";

        //fwrite(&processed_bit, sizeof(processed_bit), 1, fp_tmp);
        //fwrite(&processed_bit, sizeof(processed_bit), 1, cpu_ptr->);
        write(cpu_ptr->fd, &processed_bit, sizeof(processed_bit));
        close(cpu_ptr->fd);
        //fwrite(device_ptr, sizeof(struct blk_io_trace), 1, cpu_ptr->fd);
        //fwrite(cpu_ptr, sizeof(struct blk_io_trace), 1, cpu_ptr->fd);

    }
    return 0;
}

static int setup_out_files(void){
    int i, cpu;
    struct per_dev_info *pdi;
    int num_cpus = get_nprocs();
    for (i = 0; i < ndevices; i++) {
        pdi = &devices[i];

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
                if(resize_devices(optarg)!=0){
                    return 1;
                }
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

    memset(&rb_sort_root, 0, sizeof(rb_sort_root));

    signal(SIGINT, handle_sigint);
    signal(SIGHUP, handle_sigint);
    signal(SIGTERM, handle_sigint);

    setlocale(LC_NUMERIC, "en_US");

    if(ip_fstr){
        printf("%s\n", ip_fstr);
        ip_fp = fopen(ip_fstr, "r");
        if(!ip_fp){
            perror(ip_fstr);
            ip_fstr = NULL;
            return 1;
        }
    }

    //resize_devices(ip_fstr);

    ret = setup_out_files();
    if (!ret){
        perror("output file creation error\n");
        return ret;
    }
    unparse_genesis_time = time(NULL);
    ret = handle();

    // we have created the output files and also opened the input file
    // read each line from the file and process it now.That is it!

    return ret;
}