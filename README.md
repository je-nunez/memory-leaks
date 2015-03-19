# memory-leaks

The objective of this program is to detect memory leaks in Linux, similar to the `leaks` program in Mac OS X.

This is a brief summary of the `leaks` program in Mac OS X:

   https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/leaks.1.html 

   SYNOPSIS
         leaks pid | partial-executable-name [-nocontext] [-nostacks] [-exclude symbol] [-trace address]

   DESCRIPTION
         leaks identifies leaked memory -- memory that the application has allocated, but has been
         lost and cannot not be freed. Specifically, leaks examines a specified process's memory 
         for values may be pointers to malloc-allocated buffers. [...]

         For each leaked buffer that is found, leaks prints the address of the leaked memory and 
         its size.[...]

This OS X's `leaks` utility relies on the OS X's `Libc` library, which is not the same that in Linux 
( http://www.opensource.apple.com/source/Libc/ ), ie., it is not the GNU `gLibc` nor a replacement
library like `ucLibc`.

The GNU Libc does provide a `mtrace()` library call to debug the memory allocations:

    http://www.gnu.org/software/libc/manual/html_node/Allocation-Debugging.html 
    http://man7.org/linux/man-pages/man3/mtrace.3.html

but it requires the actual calling of `mtrace()` inside the source code (before compilation), and
that the environment variable `MALLOC_TRACE` is set to a filename where the output will be written. 
There is a Perl script able to parse this debug file pointed to by the `MALLOC_TRACE` and populated
after `mtrace()`:

    https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/mtrace.pl#l147 

The glibc also offers the `mcheck()` function and its associated environment variable `MALLOC_CHECK_`
to check that the heap is not corrupted:

    http://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html
    http://www.gnu.org/software/libc/manual/html_node/Allocation-Debugging.html

Since version 4.8, the `GNU C` and `C++` compilers can optionally add code to detect memory 
corruption and race conditions. (The `Address Sanitizer` and `Thread Sanitizer`. These 
compilers also offer an instrumentation for `UndefinedBehaviorSanitizer`.) The `LeakSanitizer` 
is an instrumentation to detect memory leak, and is part of AddressSanitizer. For more 
information:

    https://code.google.com/p/address-sanitizer/wiki/LeakSanitizer

`Electric Fence` is a library for memory debugging, which has to be compiled to your programs.

`Valgrind` is an excellent system to debug memory leaks, among many other possibilities (as memory 
corruption), but it is not easy to use it in a Production environment because of the performance 
penalty.

