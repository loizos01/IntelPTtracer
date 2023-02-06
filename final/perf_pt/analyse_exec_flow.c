#define _GNU_SOURCE

#include <stdio.h>
#include <intel-pt.h>
#include <stdbool.h>

bool exec_flow_analysis(struct pt_insn *execInstArr, int instCnt)
{

    int cnt = 0;
    for (int i = instCnt - 1; i > -1; i--)
    {
        switch (execInstArr[i].iclass)
        {
        case ptic_far_call: // SYSCALL, SYSENTER, or FAR CALL
            cnt = 1;
	        break;
        case ptic_call: // Near (function) call
            cnt--;
            if(cnt==0)
                return true;
            break;
        case ptic_return: // Near (function) return
            cnt++;
            break;
        }
    }
    return false;
}