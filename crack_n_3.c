/**
 * @file crack_n_3.c
 * @author cs
 * @brief Password cracking with MPI and pthreads
 */
#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <crypt.h>
#include <malloc.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#include <mpi.h>

/**
 * @brief Structure holding information about the program
 */
struct results {
    int combinations; ///< The number of combinations explored so far
    int partitions; ///< Number of partitions or threads
    double time; ///< Total duration
    char *name; ///< Method name
    char *answer; ///< Cracked password
    char *hash; ///< Supplied hash
};

/**
 * @brief Store found password
 */
void results_set_answer(struct results *info, char *answer) {
    info->answer = (char*)malloc(strlen(answer)*sizeof(char));
    strcpy(info->answer, answer);
}

/**
 * @brief Set iteration method name
 */
void results_set_name(struct results *info, char *name) {
    info->name = (char*)malloc(strlen(name)*sizeof(char));
    strcpy(info->name, name);
}

/**
 * @brief Store supplied hash
 */
void results_set_hash(struct results *info, char *hash) {
    info->hash = (char*)malloc(strlen(hash)*sizeof(char));
    strcpy(info->hash, hash);
}

/**
 * @brief Set number of partitions/threads
 */
void results_set_partitions(struct results *info, int partitions) {
    info->partitions = partitions;
}

/**
 * @brief Store number of explored combinations
 */
void results_set_combinations(struct results *info, int combinations) {
    info->combinations = combinations;
}

/**
 * @brief Store password cracking duration
 */
void results_set_time(struct results *info, int time) {
    info->time = time;
}

/**
 * @brief Increment the number of explored combinations
 */
void results_inc_combinations(struct results *info) {
    info->combinations += 1;
}

/**
 * @brief Get the supplied hash
 */
char *results_get_hash(struct results *info) {
    return info->hash;
}

/**
 * @brief Get the number of partions/threads
 */
int results_get_partitions(struct results *info) {
    return info->partitions;
}

/**
 * @brief Get a total number of currently explored combinations
 */
int results_get_combinations(struct results *info) {
    return info->combinations;
}

/**
 * @brief Get password cracking duration
 */
double results_get_time(struct results *info) {
    return info->time;
}

/**
 * @brief Get cracked password
 */
char *results_get_answer(struct results *info) {
    return info->answer;
}

/**
 * @brief Get iteration method name
 */
char *results_get_name(struct results *info) {
    return info->name;
}

/**
 * @brief Print all the information
 */
void results_print(struct results *results) {
    printf("Hash: %s\n", results_get_hash(results));
    printf("Approach: %s\n", results_get_name(results));
    printf("Combinations: %d\n", results_get_combinations(results));
    printf("Threads/Partitions: %d\n", results_get_partitions(results));
    printf("Answer: %s\n", results_get_answer(results));
    printf("Time: %f\n", results_get_time(results));
}

/**
 * @brief Clean-up structure
 */
void results_clean(struct results **info) {
    results_set_combinations(*info, 0);
    results_set_answer(*info, "not set");
    results_set_name(*info, "not set");
    results_set_hash(*info, "not set");
    results_set_partitions(*info, 0);
    results_set_combinations(*info, 0);
    results_set_time(*info, 0);
}

/**
 * @brief Initialise structure
 */
void results_init(struct results **info) {
    *info = malloc(sizeof(struct results));
    results_clean(info);
}

/**
 * @brief Free the memory allocated to structure
 */
void results_free(struct results **info) {
    free(*info);
    *info = NULL;
}

/**
 * @brief Command line options
 */
typedef struct options {
    char *program;
    char *help; ///< the help information
    char *filename; ///< the file containing text
    char *alphabet;
    int partitions;
    int passwords; ///< nr of passwords
    int password; ///< len of each password
    int style; ///< style

    struct {
	unsigned int h : 1, ///< Display usage information
            s : 1, ///< Set style
	    p : 1, ///< Set number of partitions
	    a : 1, ///< Set alphabet
	    m : 1, ///< 
	    n : 1, ///< 
	    f : 1; ///< Provide file
    } flags; ///< bitfield of flags
} options;

/**
 * @brief Initialize structure
 * 
 * Initialize structure <tt>options</tt> with either null
 * or zero values in fields.
 *
 * @return The pointer to the malloced memory for struct options
 * @warning The function does not free the malloced memory 
 *          see options_free()
 */
options *options_init() {
    options *ops = malloc(sizeof(*ops));
    memset(ops, 0, sizeof(*ops));
    return ops;
}

/**
 * @brief Free the memory allocated to the pointer of parts
 * @param resources address of the pointer to parts
 * @return The zero if succeful
 */
int options_free(options *ops) {
    if (ops != NULL) { /* if not already freed */
	free(ops);
	ops = NULL; /* Get rid of leftover data */
	return 0;
    } else {
	return -1;
    }
}

/**
 * @brief Setup struct 'options' using the values acquired from the command line
 * 
 * Parse arguments supplied on the command line 
 * to the program and setup <tt>struct options</tt> 
 * using the aquired values
 *
 * @param ops struct <tt>options</tt>
 * @param argc argument count
 * @param argv a pointer of tokens
 * @return The zero if succeful
 */
int options_setup(options *ops, int argc, char **argv) {

    int cmdl;
    opterr = 0; /* if other then zero,  getopt will print an error message */
    ops->program = argv[0]; /* set to the program name */
    ops->help = "-h: Display this usage information.\n"
	"-s<number>: iteration type: 0) simple 1) striding 2) block 3) striding-threaded 4) block-threaded\n"
	"-a<text>: alphabet\n"
	"-p<number>: number of threads/partitions\n"
	"-m<number>: number of passwords\n"
	"-n<number>: each password length\n"
	"-f<filepath>: access file\n";
    
    while ((cmdl = getopt(argc, argv, "hs:p:m:n:a:f:")) != -1)
	switch (cmdl) {
	case 'h':
	    ops->flags.h = 1;
	    break;
	case 's':
	    ops->flags.s = 1;
	    ops->style  = atoi(optarg);
	    break;
	case 'p':
	    ops->flags.p = 1;
	    ops->partitions  = atoi(optarg);
	    break;
	case 'm':
	    ops->flags.m = 1;
	    ops->passwords  = atoi(optarg);
	    break;
	case 'n':
	    ops->flags.n = 1;
	    ops->password  = atoi(optarg);
	    break;
	case 'a':
	    ops->flags.a = 1;
	    ops->alphabet = optarg;
	    break;
	case 'f':
	    ops->flags.f = 1;
	    ops->filename = optarg;
	    break;
	case '?':
	    if (optopt == 'f' || optopt =='a')
		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	    else if (isprint (optopt))
		fprintf (stderr, "Unknown option `-%c'.\n", optopt);
	    else
		fprintf (stderr,
			 "Unknown option character `\\x%x'.\n",
			 optopt);
	    return 1;
	default:
	    abort();
	}

    int index;
    for (index = optind; index < argc; index++)
	printf ("Non-option argument %s\n", argv[index]);
    
    return 0;
}


/**
 * @brief Access fields of options structure 
 */
bool options_has_help_flag(options *ops) { return ops->flags.h; }
bool options_has_alphabet_flag(options *ops) { return ops->flags.a; }
bool options_has_file_flag(options *ops) { return ops->flags.f; }
bool options_has_partitions_flag(options *ops) { return ops->flags.p; }
bool options_has_style_flag(options *ops) { return ops->flags.s; }
bool options_has_passwords_flag(options *ops) { return ops->flags.m; }
bool options_has_password_flag(options *ops) { return ops->flags.n; }
int options_get_style(options *ops) { return ops->style; }
char *options_get_help(options *ops) { return ops->help; }
char *options_get_alphabet(options *ops) { return ops->alphabet; }
char *options_get_filename(options *ops) { return ops->filename; }
int options_get_partitions(options *ops) { return ops->partitions; }
int options_get_passwords(options *ops) { return ops->passwords; }
int options_get_password(options *ops) { return ops->password; }
char *options_get_arg0(options *ops) { return ops->program; }

/**
 * @brief A helper function that prints all of the values in fields of options structure
 */
void options_print(options *ops, FILE *stream) {
    fprintf(stream, "Has flag?\n");
    fprintf(stream, "help: %d\n", options_has_help_flag(ops));
    fprintf(stream, "style: %d\n", options_has_style_flag(ops));
    fprintf(stream, "partitions: %d\n", options_has_partitions_flag(ops));
    fprintf(stream, "passwords: %d\n", options_has_passwords_flag(ops));
    fprintf(stream, "password: %d\n", options_has_password_flag(ops));
    fprintf(stream, "file: %d\n", options_has_file_flag(ops));
    fprintf(stream, "alphabet: %d\n", options_has_alphabet_flag(ops));
    fprintf(stream, "\nFlag arguments:\n");
    fprintf(stream, "style: %d\n", options_get_style(ops));
    fprintf(stream, "partitions: %d\n", options_get_partitions(ops));
    fprintf(stream, "passwords: %d\n", options_get_passwords(ops));
    fprintf(stream, "password: %d\n", options_get_password(ops));
    fprintf(stream, "filename: %s\n", options_get_filename(ops));
    fprintf(stream, "alphabet: %s\n", options_get_alphabet(ops));
    fprintf(stream, "\n");
}

/**
 * @brief Extract substring
 */
void substr(char *dest, char *src, int start, int length){
    memcpy(dest, src + start, length);
    *(dest + length) = '\0';
}

/**
 * @brief Measure password cracking duration
 */
int time_difference(struct timespec *start, struct timespec *finish, 
                    long long int *difference) {
    long long int ds =  finish->tv_sec - start->tv_sec; 
    long long int dn =  finish->tv_nsec - start->tv_nsec; 

    if(dn < 0 ) {
        ds--;
        dn += 1000000000; 
    } 
    *difference = ds * 1000000000 + dn;
    return !(*difference > 0);
}

/**
 * @brief Crack a three letter lowercase password
 *
 * This function can crack a three letter lowercase password. All combinations
 * that are tried are displayed and when the password is found, #, is put at the 
 * start of the line.
 */
void crack_simple_iteration(struct results *info, options *ops){
    int i, j, k;        // Loop counters
    char salt[7];       // String used in hashing the password. Need space for \0
    char plain[4];      // The combination of letters currently being checked
    plain[3] = '\0';    // Put end of string marker on password
    char *enc;          // Pointer to the encrypted password
    bool stop = false;  // Break out of nested loop

    int alphabet_size = strlen(options_get_alphabet(ops));
    
    substr(salt, results_get_hash(info), 0, 6);

    /* if (!results_get_answer(info)) { */
        for(i = 0; i <  alphabet_size && !stop; i++){
            plain[0] = ops->alphabet[i];
            for(j = 0; j < alphabet_size && !stop; j++){
                plain[1] = ops->alphabet[j];
                for(k = 0; k < alphabet_size && !stop; k++){
                    plain[2] = ops->alphabet[k];
                    enc = (char *) crypt(plain, salt);
                    results_inc_combinations(info);
                    if(strcmp(results_get_hash(info), enc) == 0){
                        results_set_answer(info, plain);
                        stop = true;
                    }
                }
            }
        }
    /* } */
}

/**
 * @brief Crack a three letter lowercase password
 *
 * This function can crack a three letter lowercase password. All combinations
 * that are tried are displayed and when the password is found, #, is put at the 
 * start of the line.
 */
void crack_striding_iteration_loop(struct results *info, options *ops, int offset) {
    int i, j, k;        // Loop counters
    char *enc;          // Pointer to the encrypted password
    char salt[7];       // String used in hashing the password. Need space for \0
    char plain[4];      // The combination of letters currently being checked
    plain[3] = '\0';    // Put end of string marker on password
    substr(salt, results_get_hash(info), 0, 6);
    bool stop = false;  // Break out of nested loop

    int alphabet_size = strlen(options_get_alphabet(ops));

    /* if (!results_get_answer(info)) { */
        for(i = offset; i < alphabet_size && !stop; i += results_get_partitions(info)){
            plain[0] = ops->alphabet[i];
            for(j = 0; j < alphabet_size && !stop; j++){
                plain[1] = ops->alphabet[j];
                for(k = 0; k < alphabet_size && !stop; k++){
                    plain[2] = ops->alphabet[k];
                    enc = (char *) crypt(plain, salt);
                    results_inc_combinations(info);
                    if(strcmp(results_get_hash(info), enc) == 0){
                        results_set_answer(info, plain);
                        stop = true;
                    }
                }
            }
        }
    /* } */
}

/**
 * @brief Crack a three letter lowercase password
 *
 * This function can crack a three letter lowercase password. All combinations
 * that are tried are displayed and when the password is found, #, is put at the 
 * start of the line.
 */
void crack_striding_iteration(struct results *info, options *ops) {

    int offset;
  
    for (offset = 0; offset < results_get_partitions(info); offset++) {
        crack_striding_iteration_loop(info, ops, offset); 
    }
  
}

typedef struct arguments {
    struct results *info;
    options *ops;
    int offset;
} arguments_t;

/**
 * @brief Crack a three letter lowercase password
 *
 * This function can crack a three letter lowercase password. All combinations
 * that are tried are displayed and when the password is found, #, is put at the 
 * start of the line.
 */
void crack_striding_iteration_threaded(struct results *info, options *ops) {

    int n_threads = results_get_partitions(info);
    pthread_t *thread = malloc(sizeof(pthread_t) * n_threads);
    arguments_t *args = malloc(sizeof(arguments_t));
    int offset;

    args->info = info;
    args->ops = ops;
    args->offset = 0;

    void *crack_striding_iteration_loop_threaded();
    
    for (offset = 0; offset < n_threads; offset++) {
        args->offset = offset;
        pthread_create(&thread[offset], NULL, crack_striding_iteration_loop_threaded, args); 
    }

    for (offset = 0; offset < n_threads; offset++) {
        pthread_join(thread[offset], NULL); 
    }

    free(args);
    free(thread);
}

/**
 * @brief Crack a three letter lowercase password
 *
 * This function can crack a three letter lowercase password. All combinations
 * that are tried are displayed and when the password is found, #, is put at the 
 * start of the line.
 */
void *crack_striding_iteration_loop_threaded(arguments_t *args) {
    crack_striding_iteration_loop(args->info, args->ops, args->offset);
}

/**
 * @brief Crack a three letter lowercase password
 *
 * This function can crack a three letter lowercase password. All combinations
 * that are tried are displayed and when the password is found, #, is put at the 
 * start of the line.
 */
void crack_block_iteration_loop(struct results *info, options *ops, int partition) {
    int i, j, k;        // Loop counters
    char *enc;          // Pointer to the encrypted password
    char salt[7];       // String used in hashing the password. Need space for \0
    char plain[4];      // The combination of letters currently being checked
    plain[3] = '\0';    // Put end of string marker on password
    substr(salt, results_get_hash(info), 0, 6);
    bool stop = false;  // Break out of nested loop

    int alphabet_size = strlen(options_get_alphabet(ops));

    int block_size = (int) ceil(alphabet_size / (double) results_get_partitions(info));
    int offset = partition*block_size; 

    /* if (!results_get_answer(info)) { */
        for(i = offset;
            i < alphabet_size && i < offset + block_size && !stop;
            i += results_get_partitions(info)){
            plain[0] = ops->alphabet[i];
            for(j = 0; j < alphabet_size && !stop; j++){
                plain[1] = ops->alphabet[j];
                for(k = 0; k < alphabet_size && !stop; k++){
                    plain[2] = ops->alphabet[k];
                    enc = (char *) crypt(plain, salt);
                    results_inc_combinations(info);
                    if(strcmp(results_get_hash(info), enc) == 0){
                        results_set_answer(info, plain);
                        stop = true;
                    }
                }
            }
        }
    /* } */
}

/**
 * @brief Crack a three letter lowercase password
 *
 * This function can crack a three letter lowercase password. All combinations
 * that are tried are displayed and when the password is found, #, is put at the 
 * start of the line.
 */
void crack_block_iteration(struct results *info, options *ops) {

    int partition;
  
    for (partition = 0; partition < results_get_partitions(info); partition++) {
        crack_striding_iteration_loop(info, ops, partition); 
    }
  
}

/**
 * @brief Crack a three letter lowercase password
 *
 * This function can crack a three letter lowercase password. All combinations
 * that are tried are displayed and when the password is found, #, is put at the 
 * start of the line.
 */
void crack_block_iteration_threaded(struct results *info, options *ops) {

    int n_threads = results_get_partitions(info);
    pthread_t *thread = malloc(sizeof(pthread_t) * n_threads);
    arguments_t *args = malloc(sizeof(arguments_t));
    int offset;

    args->info = info;
    args->ops = ops;
    args->offset = 0;

    void *crack_block_iteration_loop_threaded();
    
    for (offset = 0; offset < n_threads; offset++) {
        args->offset = offset;
        pthread_create(&thread[offset], NULL, crack_block_iteration_loop_threaded, args); 
    }

    for (offset = 0; offset < n_threads; offset++) {
        pthread_join(thread[offset], NULL); 
    }

    free(args);
    free(thread);
}

/**
 * @brief Crack a three letter lowercase password
 *
 * This function can crack a three letter lowercase password. All combinations
 * that are tried are displayed and when the password is found, #, is put at the 
 * start of the line.
 */
void *crack_block_iteration_loop_threaded(arguments_t *args) {
    crack_block_iteration_loop(args->info, args->ops, args->offset);
}

int run_program(options *ops) {
    /* If there is help flag, print out information */
    if (options_has_help_flag(ops)) {
	printf("Usage: .\%s options\n", options_get_arg0(ops));
	printf("%s", options_get_help(ops));
        return 0;
    }
    if (!options_has_style_flag(ops)) {
        printf("No style supplied.\n");
        return 0;
    } else if (options_get_style(ops) > 5) {
        printf("Only 5 iteration techniques supported.\n");
        return 0;
    }
    if (!options_has_alphabet_flag(ops)) {
        printf("No alphabet supplied.\n");
        return 0;
    }
    if (!options_has_passwords_flag(ops)) {
        printf("Number passwords in file not specified, using default 1.\n");
    }
    if (!options_has_password_flag(ops)) {
        printf("Length of password not specified.\n");
        return 0;
    }
    if (!options_has_file_flag(ops)) {
        printf("File containing passwords not specified.\n");
        return 0;
    }
    
    FILE *file;
    char buffer[options_get_password(ops)];
    char passwords[options_get_passwords(ops)][options_get_password(ops)];

    file = fopen(options_get_filename(ops),"r");

    if (!file) {
        printf("Could not open file.\n");
        return 1;
    }

    int k = 0;
    while (!feof(file)) {
        fscanf(file, "%s\n", buffer);
        strcpy(passwords[k], buffer);
        k++;
    }
    
    fclose(file);
                        
    clock_t begin, end; /* Start and end times */
    double total_time;  /* Total time */


    int n = 6;
    int i, j;

    struct results *info[n];

    for (i = 0; i < n; i++) {
        results_init(&info[i]);
    }
                        
    int ch = options_get_style(ops);
                        
    if (ch==0) {
        for (j = 0; j < options_get_passwords(ops); j++) {
            results_set_hash(info[ch], passwords[j]);
            results_set_name(info[ch], "simple");
            begin = clock();
            crack_simple_iteration(info[ch], ops);
            end = clock();
            total_time = (double) (end - begin) / CLOCKS_PER_SEC;
            results_set_time(info[ch], total_time);
            results_print(info[ch]);
            printf("\n");
        }
    }

    if ( ch==1 || ch==2 || ch==3 || ch==4 ) {
        if (!options_has_partitions_flag(ops)) {
            printf("Paritions/threads not specified. Using default number 2 of partions/threads.\n");
            results_set_partitions(info[ch], 2);
        }
        if (options_has_partitions_flag(ops)) {
            int partitions=options_get_partitions(ops);
            if (partitions < 2) {
                printf("Paritions cannot be set to less than 2 for partitioned/threaded iteration. Using default number 2 of partions/threads.\n");
                partitions = 2;
            }
            results_set_partitions(info[ch], partitions);
        }                        
        if (ch==1) {
            for (j = 0; j < options_get_passwords(ops); j++) {
                results_set_hash(info[ch], passwords[j]);
                results_set_name(info[ch], "striding");
                begin = clock();
                crack_striding_iteration(info[ch], ops);
                end = clock();
                total_time = (double) (end - begin) / CLOCKS_PER_SEC;
                results_set_time(info[ch], total_time);
                results_print(info[ch]);
                printf("\n");
            }
        }
        if (ch==2) {
            for (j = 0; j < options_get_passwords(ops); j++) {
                results_set_hash(info[ch], passwords[j]);
                results_set_name(info[ch], "block");
                begin = clock();
                crack_block_iteration(info[ch], ops);
                end = clock();
                total_time = (double) (end - begin) / CLOCKS_PER_SEC;
                results_set_time(info[ch], total_time);
                results_print(info[ch]);
                printf("\n");
            }
        }
        if (ch==3) {
            for (j = 0; j < options_get_passwords(ops); j++) {
                results_set_hash(info[ch], passwords[j]);
                results_set_name(info[ch], "striding-threaded");
                begin = clock();
                crack_striding_iteration_threaded(info[ch], ops);
                end = clock();
                total_time = (double) (end - begin) / CLOCKS_PER_SEC;
                results_set_time(info[ch], total_time);
                results_print(info[ch]);
                printf("\n");
            }
        }
        if (ch==4) {
            for (j = 0; j < options_get_passwords(ops); j++) {
                results_set_hash(info[ch], passwords[j]);
                results_set_name(info[ch], "block-threaded");
                begin = clock();
                crack_block_iteration_threaded(info[ch], ops);
                end = clock();
                total_time = (double) (end - begin) / CLOCKS_PER_SEC;
                results_set_time(info[ch], total_time);
                results_print(info[ch]);
                printf("\n");
            }
        }
    }
    
    if (ch==5) {
        j=0;
        /* for (j = 0; j < options_get_passwords(ops); j++) { */
            results_set_hash(info[ch], passwords[j]);
            results_set_name(info[ch], "parallel");
            begin = clock();
            crack_mpi(info[ch], ops);
            end = clock();
            total_time = (double) (end - begin) / CLOCKS_PER_SEC;
            results_set_time(info[ch], total_time);
            /* results_print(info[ch]); */
            /* printf("\n"); */
        /* } */
    }
    for (i = 0; i < n; i++) {
        results_free(&info[i]);
    }
    return 0;
}

/**
 * @brief Crack a three letter lowercase password
 *
 * This function can crack a three letter lowercase password. All combinations
 * that are tried are displayed and when the password is found, #, is put at the 
 * start of the line.
 */
int crack_mpi(struct results *info, options *ops) {

    struct timespec start, finish;
    int size, rank;

    MPI_Init(NULL, NULL);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    printf("I am %d of %d\n", rank, size);

    if (rank == 0) {   
        clock_gettime(CLOCK_MONOTONIC, &start);
   
        MPI_Status status;
        MPI_Request request[65]; // Assume there are at most 65 processes.
        int done = 0;
        int i;
        int length;
        char buffer[100]; // assume string length is less than 100

        while (!done) {
            MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &done, &status);

            if (done==1) {

                MPI_Recv(&length, 1, MPI_INT, status.MPI_SOURCE, status.MPI_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                printf("string to be received has %d characters\n", length);
                MPI_Recv(buffer, length+1, MPI_INT, status.MPI_SOURCE, status.MPI_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                printf("Process %d received %s\n", rank, buffer); 
                results_set_answer(info, buffer);
                
                for(i=1;i<size;i++){
                    if(i!=status.MPI_SOURCE){
                        printf("sending done to process %d\n", i);
                        MPI_Isend(&done, 1, MPI_INT, i, 0, MPI_COMM_WORLD, &request[i]);
                    }
                }
            }          
        }
    } else {
        int done = 0;
        MPI_Status status;
        MPI_Request request;

        int i, j, k;        // Loop counters

        char salt[7];       // String used in hashing the password. Need space for \0
        char plain[4];      // The combination of letters currently being checked
        plain[3] = '\0';    // Put end of string marker on password
        char *enc;          // Pointer to the encrypted password
        /* bool stop = false;  // Break out of nested loop */
        int alphabet_size = strlen(options_get_alphabet(ops));
        substr(salt, results_get_hash(info), 0, 6);

        for (i = rank; i < alphabet_size && !done; i += size){
            plain[0] = ops->alphabet[i];
            printf("process %d exploring first letter = %c\n", rank, plain[0]);
            for(j=0;j<alphabet_size && !done;j++){
                MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &done, &status);
                if(done){
                    printf("process %d has received done signal\n", rank);
                    break;
                }
                plain[1] = ops->alphabet[j];
                for (k=0;k<alphabet_size && !done;k++) {
                    plain[2] = ops->alphabet[k];
                    enc = (char *) crypt(plain, salt);
                    results_inc_combinations(info);
                    if (strcmp(results_get_hash(info), enc) == 0) {
                        printf("process %d has found solution %s\n", rank, plain);
                        int length = strlen(plain);
                        MPI_Send(&length, 1, MPI_INT, 0, 0, MPI_COMM_WORLD);
                        MPI_Send(plain, length+1, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
                        printf("status ");
                        done=1;
                    }
                }
            }
        }
        printf("process %d is about to finish\n", rank);
    }
    MPI_Barrier(MPI_COMM_WORLD);
    MPI_Finalize(); 

    if (rank == 0) {
        long long int time_elapsed;
        clock_gettime(CLOCK_MONOTONIC, &finish);
        time_difference(&start, &finish, &time_elapsed);
        printf("Time elapsed was %lldns or %0.9lfs\n", time_elapsed,
               (time_elapsed/1.0e9));
    }
    return 0;
}

/**
 * @brief Entry point v1
 */
int main (int argc, char **argv) {
    options *ops = options_init(); /* initialize options with null values */
    options_setup(ops, argc, argv); /* assign values to fields of options structure
                                       using command line arguments */

    /* options_print(ops, stdout); */

    run_program(ops); /* use command line options */
    options_free(ops); /* free the allocated memory */
    return 0;
} 

/**
 * @brief Entry point v0
 */
int main_v0(int argc, char *argv[]) {

    FILE *file;
    char buffer[93];
    char passwords[100][93];

    file = fopen("data/26_3_100.txt","r");

    if (!file) {
        printf("could not open file\n");
        return 1;
    }

    int k = 0;
    while (!feof(file)) {
        fscanf(file, "%s\n", buffer);
        strcpy(passwords[k], buffer);
        k++;
    }
    
    fclose(file);

    clock_t begin, end;
    double total_time;
  
    struct results *info[3];

    for (int i = 0; i < 3; i++) {
        results_init(&info[i]);
    }

    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 100; j++) {
            results_set_hash(info[i], passwords[j]);
            results_set_name(info[i], "simple");
            begin = clock();
            crack_simple_iteration(info[i]);
            end = clock();
            total_time = (double) (end - begin) / CLOCKS_PER_SEC;
            results_set_time(info[i], total_time);
            results_print(info[i]);
            printf("\n");
        }
    }

    return 0;
}
