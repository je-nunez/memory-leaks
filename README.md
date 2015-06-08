# memory-leaks

# WIP

This project is a *work in progress*. The implementation is *incomplete* and subject to change. The documentation can be inaccurate.

# Stale

This project is *stale* for the time being.

The development of it was diverted somehow to the other project `a_gnu_libc_interceptor_via_rtld_audit` at:

    https://github.com/je-nunez/a_gnu_libc_interceptor_via_rtld_audit

that also uses the same underlying technology, the `LibC RTLD Run-time Audit`:

    http://man7.org/linux/man-pages/man7/rtld-audit.7.html

There is a difference between both projects, and is that `a_gnu_libc_interceptor_via_rtld_audit` does a general common analysis of each library call `independently of each other` (profiling each), but this project tries to interpret logically the `inter-relationship between different calls` (eg., to interpret the address of the heap between `malloc()`s and `free()`s), so their use is different. This project will be resumed in some time, since it receives like a hologram between the calls and uses it to build a finite-state machine: this technique may be used for the relationship between other library calls which are related, not only those of heap-memory allocation.

# Description

The objective of this program is to detect memory leaks in Linux, similar to the `leaks` program in Mac OS X.

This is a brief summary of the `leaks` program in Mac OS X:

    https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/leaks.1.html 

    SYNOPSIS
         leaks pid | partial-exec-name [-nocontext] [-nostacks] [-exclude symbol] [-trace address]

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

`Electric Fence` is a library for memory debugging, which has to be linked to your programs.

Related also to glibc, but in another lever, it also offers `SystemTap` probes for debugging memory allocations (the `libc` SystemTap provider).

    http://www.gnu.org/software/libc/manual/html_node/Internal-Probes.html

`Valgrind` is an excellent system to debug memory leaks, among many other possibilities (as memory 
corruption), but it is not easy to use it in a Production environment because of the performance 
penalty.

Inside the Linux kernel, newer versions of it ( >= 3.19 ) offer the possibility of `Kernel Address Sanitizer`, to detect memory corruption in kernel-mode, and is
enabled with the config option `CONFIG_KASAN = y` when built with the latest GCC compiler (see above for the `Address Sanitizer` of GCC but in user-mode):

    https://www.kernel.org/doc/Documentation/kasan.txt
    http://address-sanitizer.googlecode.com/svn/wiki/AddressSanitizerForKernel.wiki

