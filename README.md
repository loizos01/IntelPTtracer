# IntelPTtracer

Hi markus,

I really appreciate taking the time to take a look, this means a lot to me.

The perf_pt folder contains the collect,decode and ptxed_util files. I am extending a library afound written in rust/C thats why there is some garbage code in them. Ptxed_util is a stripped down version of ptxed tool you provided with libipt.

test2_copy is the main file, which contains the dummy code we discussed in the issue #93. The issue am facing is what we discussed in #93

the machine am using for development is running libipt version = ffe1631be3dad2dc286529e3e05d552043d626f0 and 
XED_V = f7191e268c3ee17fc8c9b8d9bd3eee7159f29556

This project is part of my bachelor thesis "Defending ROP attacks using Intel PT"

Thank you,
Loizos Nicolaou
