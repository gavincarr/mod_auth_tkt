Test Instructions
=================

Requirements:

- Apache::TestRun, from the mod_perl project



1. To run the test suite against the currently configured apache version:

   make test
   # (see the Makefile for details, but it's basically just running ./TEST)



2. To run a single unit test e.g. 01_basic.t:

   ./TEST 01_basic.t


3. To run a single unit test through gdb:

   # (make sure you've run with './configure --debug' for debug symbols)
   ./TEST -start-httpd -one-process
   # in another window
   gdb /usr/sbin/httpd PID
   # in test window
   ./TEST 01_basic.t


