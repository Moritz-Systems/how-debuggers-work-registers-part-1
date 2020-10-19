/**
 * An example how to get and set register values via ptrace(2).
 *
 * To the extent possible under law, Moritz Systems has waived all
 * copyright and related or neighboring rights to this work.
 */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <machine/reg.h>

#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    int ret;
    pid_t pid = fork();
    assert(pid != -1);

    if (pid == 0) {
        uint64_t rax = 0x0001020304050607;
        printf("RAX in child before trap: 0x%016" PRIx64 "\n", rax);

        /* child -- debugged program */
        /* request tracing */
        ret = ptrace(PT_TRACE_ME, 0, NULL, 0);
        assert(ret != -1);

        __asm__ __volatile__ (
            "finit\n\t"
            "fldz\n\t"
            "fld1\n\t"
            "int3\n\t"
            : "+a"(rax)
            :
            : "st"
        );

        printf("RAX in child after trap: 0x%016" PRIx64 "\n", rax);
        _exit(0);
    }

    /* parent -- the debugger */
    /* wait for the child to become ready for tracing */
    pid_t waited = waitpid(pid, &ret, 0);
    assert(waited == pid);
    assert(WIFSTOPPED(ret));
    assert(WSTOPSIG(ret) == SIGTRAP);

    struct reg gpr;
    struct fpreg fpr;

    /* get GPRs and FPRs */
    ret = ptrace(PT_GETREGS, pid, &gpr, 0);
    assert (ret == 0);
    ret = ptrace(PT_GETFPREGS, pid, &fpr, 0);
    assert (ret == 0);

    printf("RAX from PT_GETREGS: 0x%016" PRIx64 "\n",
            gpr.regs[_REG_RAX]);
    printf("ST(0) (raw) from PT_GETFPREGS: 0x%04" PRIx16
            "%016" PRIx64 "\n",
            fpr.fxstate.fx_87_ac[0].r.f87_exp_sign,
            fpr.fxstate.fx_87_ac[0].r.f87_mantissa);
    printf("ST(1) (raw) from PT_GETFPREGS: 0x%04" PRIx16
            "%016" PRIx64 "\n",
            fpr.fxstate.fx_87_ac[1].r.f87_exp_sign,
            fpr.fxstate.fx_87_ac[1].r.f87_mantissa);
    gpr.regs[_REG_RAX] = 0x0f0e0d0c0b0a0908;
    printf("RAX set via PT_SETREGS: 0x%016" PRIx64 "\n",
            gpr.regs[_REG_RAX]);

    /* set GPRs and resume the program */
    ret = ptrace(PT_SETREGS, pid, &gpr, 0);
    assert (ret == 0);
    ret = ptrace(PT_CONTINUE, pid, (void*)1, 0);
    assert(ret == 0);

    /* wait for the child to exit */
    waited = waitpid(pid, &ret, 0);
    assert(waited == pid);
    assert(WIFEXITED(ret));
    assert(WEXITSTATUS(ret) == 0);

    return 0;
}
