
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <ftw.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>


/* Standard filename of the Glibc dynamic audit library */

#define NAME_LIB_LATRACE "libltaudit.so"

static int exit_flag_set_by_a_signal = 0;

static int
setup_inotify_dir_for_new_trace_files(size_t in_size_array,
              char * in_out_parm_dir_watched_by_inotify)
{
  in_out_parm_dir_watched_by_inotify[0] = '\0';

  char directory_to_watch_for_trace_files[PATH_MAX];

  /* Build the directory path where the liblatrace will leave the new
   * file it generates */
  int current_epoch_time = time(NULL);
  pid_t current_pid = getpid();

  srand(current_pid+current_epoch_time);
  int random_salt = rand();

  snprintf(directory_to_watch_for_trace_files,
     sizeof directory_to_watch_for_trace_files,
     "/tmp/memleaks.%ld.%d.%d",
     current_epoch_time, current_pid, random_salt);

  struct stat stat_result;
  int         status;

  if (stat(directory_to_watch_for_trace_files, &stat_result)) {
    if (mkdir(directory_to_watch_for_trace_files, S_IRWXU)) {
      char err_msg[PATH_MAX+256];
      snprintf(err_msg, sizeof err_msg, "ERROR: mkdir failed for %s",
         directory_to_watch_for_trace_files);
      perror(err_msg);
      return -1;
    }
  }

  int inotify_watch_fd ;
  if (-1 == (inotify_watch_fd = inotify_init())) {
    perror("inotify_init failed");
    return -1;
  }

  if (-1 == inotify_add_watch(inotify_watch_fd,
            directory_to_watch_for_trace_files, IN_CREATE)) {
    perror("inotify_add_watch failed");
    return -1;
  }

  strncpy(in_out_parm_dir_watched_by_inotify,
    directory_to_watch_for_trace_files, in_size_array);
  return inotify_watch_fd;
}

#define LOCATION_LIB_LATRACE "/usr/lib64/libltaudit.so.0.5.11"


static int
search_libltaudit(char * const * in_dir_tree, size_t in_size_buf, 
                  char * in_out_real_location_of_libltaudit)
{
  int libltaudit_found = 0;

  FTS *dir_tree;
  FTSENT *dir_entry;
  int fts_options = FTS_COMFOLLOW | FTS_LOGICAL | FTS_NOCHDIR;
  /* fprintf(stderr, "DEBUG: transversing with fts_open %s\n", in_dir_tree); */
  if ((dir_tree = fts_open(in_dir_tree, fts_options, NULL)) == NULL) 
     return 0;

  while ((0 == libltaudit_found) && 
                ((dir_entry = fts_read(dir_tree)) != NULL)) {

    // fprintf(stderr, "DEBUG: analyzing %s\n", dir_entry->fts_path);

    if((dir_entry->fts_name == strstr(dir_entry->fts_name, NAME_LIB_LATRACE))
       && (dir_entry->fts_info == FTS_F)) {
         // fprintf(stderr, "DEBUG: tentative %s\n", dir_entry->fts_path);
         /* Check if it is a file and if current user has +RX permission */
         // fprintf(stderr, "DEBUG: checking access %s\n", dir_entry->fts_path);
         if (0 == access(dir_entry->fts_path, F_OK | R_OK | X_OK)) {
            strncpy(in_out_real_location_of_libltaudit, dir_entry->fts_path,
                    in_size_buf);
            libltaudit_found = 1;
            break;
         }
    }
  }
  fts_close(dir_tree);

  return libltaudit_found;
}


static int
search_libltaudit_in_search_path(size_t in_size_buf, 
                                 char * in_out_real_location_of_libltaudit)
{
  char * standard_library_locations[] = { "/usr/lib64", "/usr/lib", NULL };

  /* Try to find the libltaudit in the LD_LIBRARY_PATH override-search,
   * since this is what Linux does, using this override first */

  char * ld_libr_path = getenv("LD_LIBRARY_PATH");
  if (ld_libr_path == NULL) 
    goto try_to_find_libltaudit_in_default_libr_directories;

  fprintf(stderr, "DEBUG: transversing LD_LIBRARY_PATH %s\n", ld_libr_path); 
  char * current_libr_path = ld_libr_path;
  char * position_colon;
  char * directory_vector_for_fts_open[2]; 
  char current_directory_in_ld_libr_path[NAME_MAX]; 
  
  do {
    position_colon = strchr(current_libr_path, ':');
    size_t number_of_chars_to_copy;
    if (position_colon == NULL)
       number_of_chars_to_copy = sizeof current_directory_in_ld_libr_path;
    else {
       number_of_chars_to_copy = position_colon - current_libr_path;
       /* don't trust LD_LIBRARY_PATH, but sanitize it */
       if (number_of_chars_to_copy > sizeof current_directory_in_ld_libr_path)
           number_of_chars_to_copy = sizeof current_directory_in_ld_libr_path;
    }

    strncpy(current_directory_in_ld_libr_path, current_libr_path,
	                number_of_chars_to_copy);

    directory_vector_for_fts_open[0] = current_directory_in_ld_libr_path;
    directory_vector_for_fts_open[1] = NULL;

    if (search_libltaudit(directory_vector_for_fts_open, in_size_buf, 
                          in_out_real_location_of_libltaudit) != 0) 
       return 1;  /* libltaudit was found */
   
    if (position_colon != NULL) current_libr_path = position_colon+1;
  } while (position_colon != NULL);

  /* Try as a last effort the standard library locations */

try_to_find_libltaudit_in_default_libr_directories:

  fprintf(stderr, "DEBUG: transversing std lib directories\n"); 
  if (search_libltaudit(standard_library_locations,
                          in_size_buf, 
                          in_out_real_location_of_libltaudit) != 0) 
       return 1;  /* libltaudit was found in the standard library locations */
    
  return 0; /* libltaudit was not found */
}


static pid_t
run_traced_program(char ** traced_programs_argv)
{
  /* Use the "latrace" hologram subsystem in the GNU libc.
   * See source code of the latrace process, in particular
   * the function run_child() in run.c. For information:
   *
   *     man latrace(1)
   *     man rtld-audit(7)
   *
   * (Credit is due to their respective authors) */

  int forked_pid = 0;
  if ((forked_pid = fork()) == 0) {

    /* This is the child process */
    char audit_lib[PATH_MAX];
  
    if (search_libltaudit_in_search_path(sizeof audit_lib, audit_lib) != 1) {
      /* We couldn't find a libltaudit.so in this system */
      fprintf(stderr, "%s not found in this system.\n", NAME_LIB_LATRACE);
      fprintf(stderr, "Please set LD_LIBRARY_PATH to where to find it.\n");
      exit(2);
    }

    setenv("LD_AUDIR", audit_lib, 1);
    setenv("LT_DIR", "/tmp/", 1);

    if (execvp(traced_programs_argv[0], traced_programs_argv) == -1) {
      /* Exec failed */
      fprintf(stderr, "ERROR: %s couldn't be executed. Error: %s\n",
                  traced_programs_argv[0], strerror(errno));
      exit(1);
    }
  } else if (forked_pid < 0) {
         /* fork itself failed */
         perror("couldn't fork a subprocess");
  }
}



static int
open_new_liblatrace_fifo(int fd_notify, char *dir, pid_t *new_thread_id)
{
  unsigned char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
  struct inotify_event *inotif_event = (struct inotify_event*) buf;

  if (-1 == read(fd_notify, inotif_event, sizeof buf)) {
     perror("read notify failed");
     return -1;
  }

  sscanf(inotif_event->name, "fifo-%d", new_thread_id);

  char fifo_fname[NAME_MAX];
  int fifo_fd;

  snprintf(fifo_fname, sizeof fifo_fname, "%s/%s", dir, inotif_event->name);

  if (-1 == (fifo_fd = open(fifo_fname, O_RDONLY)))
     perror("open fifo failed");

  return fifo_fd;
}


struct lt_fifo_mbase {
#define FIFO_MSG_TYPE_ENTRY   1
#define FIFO_MSG_TYPE_EXIT    2
        uint32_t type;
        struct timeval tv;
        pid_t tid;
        int len; /* the rest of the message size */
};

/* symbol message */
struct lt_fifo_msym {
        struct lt_fifo_mbase h;

        int sym;
        int lib;
        int arg;
        int argd;
        char data[0];
};


static int 
lt_fifo_recv(struct lt_config_app *cfg, struct lt_thread *t, void *buf,
                     int bufsize)
{
  ssize_t size;
  struct lt_fifo_mbase *h = buf;

  if (-1 == (size = read(t->fifo_fd, h, sizeof(struct lt_fifo_mbase)))) {
    perror("read failed");
    return -1;
  }

  if (size == 0)
    return -1;

  if ((size + h->len) > bufsize) {
    printf("thread %d - buffer max size reached\n", t->tid);
    return -1;
  }

  if (-1 == (size = read(t->fifo_fd, buf + sizeof(*h), h->len))) {
    perror("read failed");
    return -1;
  }

  return 0;
}



static int 
process_fifo(struct lt_config_app *cfg, struct lt_thread *t)
{
  static char buf[FIFO_MSG_MAXLEN];
  struct lt_fifo_mbase *mbase = (struct lt_fifo_mbase*) buf;
  struct lt_fifo_msym *msym = (struct lt_fifo_msym*) buf;

  if (-1 == lt_fifo_recv(cfg, t, mbase, FIFO_MSG_MAXLEN))
          return -1;

  if ((FIFO_MSG_TYPE_ENTRY != mbase->type) &&
                  (FIFO_MSG_TYPE_EXIT  != mbase->type)) {
          PRINT_VERBOSE(cfg, 1, "unexpected message type %d\n",
                                            mbase->type);
          return -1;
  }

  if (lt_sh(cfg, counts))
          return lt_stats_sym(cfg, t, msym);

  if (FIFO_MSG_TYPE_ENTRY == msym->h.type) {
          /* Entry intro library call */
          lt_out_entry(cfg->sh, &msym->h.tv, msym->h.tid,
                                           t->indent_depth,
                                           msym->data + msym->sym,
                                           msym->data + msym->lib,
                                           msym->data + msym->arg,
                                           msym->data + msym->argd);

  } else if (FIFO_MSG_TYPE_EXIT == msym->h.type) {
          /* Return from library call */
          lt_out_exit(cfg->sh, &msym->h.tv, msym->h.tid,
                                          t->indent_depth,
                                          msym->data + msym->sym,
                                          msym->data + msym->lib,
                                          msym->data + msym->arg,
                                          msym->data + msym->argd);
  }

  return 0;
}


static int
process_homomorphic_finite_state_machine_on_traced_program(
                         char * subset_of_libc_functions_to_project_on[],
                         pid_t running_traced_program_started_with_liblatrace,
                         const char * dir_with_liblatrace_reports,
                         int inotify_fd_for_new_trace_files
                      )
{
  pid_t traced_pid = running_traced_program_started_with_liblatrace;

  int number_running_threads = 0, getin = 1, exit_status;
  fd_set cfg_set, wrk_set;
  int max_select_fd = 0;

  typedef struct _traced_thread_stat {
    struct _traced_thread_stat *list_forward;
    struct _traced_thread_stat *list_backward;
    int fifo_fd;
  } traced_threads_stat ;

  traced_threads_stat * list_traced_threads = NULL;

  /* prepare our select */
  FD_ZERO(&cfg_set);
  FD_SET(inotify_fd_for_new_trace_files, &cfg_set);
  max_select_fd = inotify_fd_for_new_trace_files;

  while((waitpid(traced_pid, &exit_status, WNOHANG) == 0) ||
    /* let all the thread fifo close */
    (number_running_threads) ||
    /* Get inside at least once, in case the traced program
     * finished before we got here. Another case is if there's
     * an input on notify descriptor, we want to try another
     * select to be sure we dont miss any other event. */
    (getin))
  {


    struct timeval tv = { 0, 100 };
    int number_of_ready_fds;

    /* we got a signal, there's nothing to wait for.. */
    if (exit_flag_set_by_a_signal)
       break;

    getin = 0;
    wrk_set = cfg_set;

    number_of_ready_fds = select(max_select_fd + 1, &wrk_set, NULL, NULL, &tv);
    if (-1 == number_of_ready_fds) {
      if (errno != EINTR)
        perror("select failed");
      return -1;
    } else if (number_of_ready_fds <= 0)
             continue;

    /* There are file-descriptors ready to be be read */
    if (FD_ISSET(inotify_fd_for_new_trace_files, &wrk_set)) {
      int fd;
      pid_t thread_id;

      /* try to get any event at least once again */
      getin = 1;

      int fd_latrace_fifo;
      fd_latrace_fifo = open_new_liblatrace_fifo(inotify_fd_for_new_trace_files,
                                                 dir_with_liblatrace_reports,
                                                 &thread_id);
      if (-1 == fd_latrace_fifo)
        continue;

      traced_threads_stat * new_traced_thread;
      new_traced_thread = (traced_threads_stat *) malloc(
                                                  sizeof(traced_threads_stat));

      if (NULL == new_traced_thread) {
        perror("malloc failed");
        close(fd);
        continue;
      } else {
        memset((void *)new_traced_thread, 0, sizeof(traced_threads_stat));

        insque(new_traced_thread, list_traced_threads);
        list_traced_threads = new_traced_thread ;
      }

      number_running_threads++;

      FD_SET(fd, &cfg_set);
      if (fd_latrace_fifo > max_select_fd)
        max_select_fd = fd_latrace_fifo ;

      number_of_ready_fds--;
    }

    if (number_of_ready_fds == 0)
      continue;

    /* process fifo */
    traced_threads_stat * t;
    for(t = list_traced_threads; t ; t = t->list_forward) {
      if (FD_ISSET(t->fifo_fd, &wrk_set)) {
        if (-1 == process_fifo(cfg, t)) {
          FD_CLR(t->fifo_fd, &cfg_set);
          /* maintain state per thread */
          number_running_threads--;
        }
        number_of_ready_fds--;
      }
    }
  }

  return exit_status;
}


/*
 *     MAIN   PROGRAM
 */

int
main(int argc, char ** argv)
{
  char * memory_allocation_functions[] = {"malloc", "calloc", "realloc", "free"};

  char dir_with_new_liblatrace_files[PATH_MAX];
  int inotify_fd_for_new_trace_files =
     setup_inotify_dir_for_new_trace_files(sizeof dir_with_new_liblatrace_files,
                                           dir_with_new_liblatrace_files);

  pid_t traced_program_pid = run_traced_program(argv + 1);

  process_homomorphic_finite_state_machine_on_traced_program(
         memory_allocation_functions,
         traced_program_pid,
         dir_with_new_liblatrace_files,
         inotify_fd_for_new_trace_files
         );

  /* TODO: parse output of latrace, taking the hologram only
   * of the finite state machine on memory_allocation_functions[],
   * only on the functions in this array, and ignoring all the other
   * functions unrelated to memory allocation in the hologram of
   * the traced process */

}


