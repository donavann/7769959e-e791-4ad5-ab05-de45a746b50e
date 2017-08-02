Assumptions:

1) Pulling stats on a server without any hash requests yields an average time of zero (division by zero protection)
2) I return errors with an extra linefeed to improve readability

Regarding Shutdown:

I added an additional URL that can be called to initiate the shutdown sequence.  Obviously this is a very large security hole.  For the purposes of this exercise I used this method rather than tying in a signal handler, semaphore monitor, etc.

To perform a shutdown: curl http://localhost:8888/shutdown 

Testing:

I have included some basic bash scripts in the scripts directory.  I presume JumpCloud has a test harness in place to actually test the code following a review.

Starting:

To start the application, simply use "go run hasher.go" from the repository root directory

The web server listens on port 8888



