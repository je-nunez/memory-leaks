
#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include <string.h>
#include <stdlib.h>


/* FIXME: take the install directory and installed version dinamically,
 * according to the system */
#define LOCATION_LIB_LATRACE "/usr/lib64/libltaudit.so.0.5.11"

static void
run_traced_program( char ** traced_programs_argv )
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
    if ( ( forked_pid = fork() ) == 0 ) {

         /* This is the child process */
         char audit_lib[PATH_MAX];
         strncpy( audit_lib, LOCATION_LIB_LATRACE,
		  sizeof audit_lib );

         setenv("LD_AUDIR", audit_lib, 1);
         setenv("LT_DIR", "/tmp/", 1);

         if ( execvp( traced_programs_argv[0],
                      traced_programs_argv+1 ) == -1 ) {
               /* Exec failed */
               fprintf(stderr,
		       "ERROR: %s couldn't be executed. Error: %s\n",
		       traced_programs_argv[0], strerror( errno ));
               exit(1);
         }
    } else {
    }
}


int
main(int argc, char ** argv)
{
    const char const * memory_allocation_functions[] = { "malloc",
	                                                     "calloc",
	                                                     "realloc",
	                                                     "free" };

    run_traced_program( argv + 1 );
}


