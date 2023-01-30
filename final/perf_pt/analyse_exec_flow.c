#define _GNU_SOURCE

#include <stdio.h>
#include <intel-pt.h>

bool exec_flow_analysis(struct pt_insn *execInst, int count)
{
    int flag = 0;

    for (int i = count - 1; i > -1; i--)
    {
        switch (execInst[i].iclass)
        {
        case ptic_far_call: // SYSCALL, SYSENTER, or FAR CALL
            flag = 1;
        case ptic_call: // Near (function) call
            if (flag == 1)
            {
                return true;
            }
            break;
        case ptic_return: // Near (function) return
            if (flag == 1)
            {
                return false;
            }
            break;
        }
    }
}