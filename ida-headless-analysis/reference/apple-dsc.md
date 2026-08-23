# IDA 9.4 Apple Dyld Shared Cache Workflow

IDA 9.4 substantially reworks Dyld Shared Cache loading/analysis. Use the 9.4 loader/model rather
than carrying forward assumptions from older IDA databases.

Workflow:

1. let IDA 9.4 load the DSC and complete auto-analysis;
2. identify the specific image/framework before broad searching;
3. preserve Objective-C selectors, method prototypes, Swift metadata and cross-image references;
4. use exact byte string search only inside relevant mapped ranges when possible;
5. use bounded xrefs/path tracing rather than loading huge cross-cache graphs into Claude;
6. treat missing relationships as a reason to inspect the 9.4 DSC APIs/loader state, not immediate
   evidence that the reference does not exist;
7. use the IDA 9.4 SDK `dscu.h` facilities through IDAPython/C++ only when Domain API does not expose
   the required cache operation.

DSCs are extremely name-heavy. Token budgets matter more here than in ordinary executables.
