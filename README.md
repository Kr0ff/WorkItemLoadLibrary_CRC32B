# WorkItemLoadLibrary_CRC32B

This is a method of using WorkItem APIs to queue them to load a module. This version was modified to support string hashing via CRC32B.

Original research done by @MDSecLabs and credits to:
* Peter Winter-Smith (@peterwintrsmith)
* Proofpoint threatinsight team for their detailed analysis
* rad9800 for the initial implementation

Improvements to do:
* Implement indirect syscalls [N/A]

Research references:
https://github.com/rad9800/misc/blob/main/bypasses/WorkItemLoadLibrary.c
