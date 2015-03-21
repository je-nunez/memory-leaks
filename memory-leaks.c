
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/limits.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/inotify.h>


/* FIXME: take the install directory and installed version dinamically,
 * according to the running system */
#define LOCATION_LIB_LATRACE "/usr/lib64/libltaudit.so.0.5.11"

static int
setup_inotify_dir_for_new_trace_files(size_t in_size_array, 
				      char * in_out_parm_dir_watched_by_inotify)
{
  in_out_parm_dir_watched_by_inotify[0] = '\0'; 

  char directory_to_watch_for_trace_files[PATH_MAX];

  /* Build the directory path where the liblatrace will leave the new
   * file it generates */
  int current_epoch_time = time(NULL);
  int random_salt = rand();
  pid_t current_pid = getpid();

  snprintf(directory_to_watch_for_trace_files, 
	   sizeof directory_to_watch_for_trace_files,
	   "/tmp/memleaks.%ld.%d.%d", 
	   current_epoch_time, current_pid, random_salt);

  struct stat stat_result;
  int         status;

  if (stat(directory_to_watch_for_trace_files, &stat_result)) {
    if (mkdir(directory_to_watch_for_trace_files, S_IRWXU)) {
      char err_msg[PATH_MAX+256];
      snprintf(err_msg, sizeof err_msg, "mkdir failed for %s",
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


static void
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
    strncpy(audit_lib, LOCATION_LIB_LATRACE, sizeof audit_lib);

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


int
main(int argc, char ** argv)
{
  const char const * memory_allocation_functions[] = { "malloc",
                                                       "calloc",
                                                       "realloc",
                                                       "free" };

  char dir_with_new_liblatrace_files[PATH_MAX];
  int new_trace_files_inotify_fd = 
     setup_inotify_dir_for_new_trace_files(sizeof dir_with_new_liblatrace_files,
					   dir_with_new_liblatrace_files);

  run_traced_program(argv + 1);

  /* TODO: parse output of latrace, taking the hologram only
   * of the finite state machine on memory_allocation_functions[],
   * only on the functions in this array, and ignoring all the other
   * functions unrelated to memory allocation in the hologram of
   * the traced process */

}


