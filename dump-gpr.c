/**
 * An example how to copy values of all General Purpose Registers
 * into C variables, and print them.
 *
 * To the extent possible under law, Moritz Systems has waived all
 * copyright and related or neighboring rights to this work.
 */

#include <stdio.h>
#include <stdint.h>

enum {
    R_RAX, R_RBX, R_RCX, R_RDX, R_RSI, R_RDI, R_RBP, R_RSP,
    R_R8, R_R9, R_R10, R_R11, R_R12, R_R13, R_R14, R_R15,
    R_RIP, R_RFLAGS,
    R_LENGTH
};

enum {
    S_CS, S_DS, S_ES, S_FS, S_GS, S_SS,
    S_LENGTH
};

int main()
{
    uint64_t gpr[R_LENGTH];
    uint16_t seg[S_LENGTH];

    asm volatile (
        /* fill registers with random data */
        "mov $0x0102030405060708, %%rax\n\t"
        "mov $0x1112131415161718, %%rbx\n\t"
        "mov $0x2122232425262728, %%rcx\n\t"
        "mov $0x3132333435363738, %%rdx\n\t"
        "mov $0x4142434445464748, %%rsi\n\t"
        "mov $0x5152535455565758, %%rdi\n\t"
        /* RBP is used for frame pointer, RSP is stack pointer */
        "mov $0x8182838485868788, %%r8\n\t"
        "mov $0x9192939495969798, %%r9\n\t"
        "mov $0xa1a2a3a4a5a6a7a8, %%r10\n\t"
        "mov $0xb1b2b3b4b5b6b7b8, %%r11\n\t"
        "mov $0xc1c2c3c4c5c6c7c8, %%r12\n\t"
        "mov $0xd1d2d3d4d5d6d7d8, %%r13\n\t"
        "mov $0xe1e2e3e4e5e6e7e8, %%r14\n\t"
        "mov $0xf1f2f3f4f5f6f7f8, %%r15\n\t"

        /* dump GPRs */
        "mov %%rax, %[rax]\n\t"
        "mov %%rbx, %[rbx]\n\t"
        "mov %%rcx, %[rcx]\n\t"
        "mov %%rdx, %[rdx]\n\t"
        "mov %%rsi, %[rsi]\n\t"
        "mov %%rdi, %[rdi]\n\t"
        "mov %%rbp, %[rbp]\n\t"
        "mov %%rsp, %[rsp]\n\t"
        "mov %%r8, %[r8]\n\t"
        "mov %%r9, %[r9]\n\t"
        "mov %%r10, %[r10]\n\t"
        "mov %%r11, %[r11]\n\t"
        "mov %%r12, %[r12]\n\t"
        "mov %%r13, %[r13]\n\t"
        "mov %%r14, %[r14]\n\t"
        "mov %%r15, %[r15]\n\t"
        /* dump RIP */
        "lea (%%rip), %%rbx\n\t"
        "mov %%rbx, %[rip]\n\t"
        "mov %[rbx], %%rbx\n\t"
        /* dump segment registers */
        "mov %%cs, %[cs]\n\t"
        "mov %%ds, %[ds]\n\t"
        "mov %%es, %[es]\n\t"
        "mov %%fs, %[fs]\n\t"
        "mov %%gs, %[gs]\n\t"
        "mov %%ss, %[ss]\n\t"
        /* dump RFLAGS */
        "pushfq\n\t"
        "popq %[rflags]\n\t"

        : [rax] "=m"(gpr[R_RAX]), [rbx] "=m"(gpr[R_RBX]),
          [rcx] "=m"(gpr[R_RCX]), [rdx] "=m"(gpr[R_RDX]),
          [rsi] "=m"(gpr[R_RSI]), [rdi] "=m"(gpr[R_RDI]),
          [rbp] "=m"(gpr[R_RBP]), [rsp] "=m"(gpr[R_RSP]),
           [r8] "=m"(gpr[ R_R8]), [ r9] "=m"(gpr[ R_R9]),
          [r10] "=m"(gpr[R_R10]), [r11] "=m"(gpr[R_R11]),
          [r12] "=m"(gpr[R_R12]), [r13] "=m"(gpr[R_R13]),
          [r14] "=m"(gpr[R_R14]), [r15] "=m"(gpr[R_R15]),
          [rip] "=m"(gpr[R_RIP]), [rflags] "=m"(gpr[R_RFLAGS]),
          [cs] "=m"(seg[S_CS]), [ds] "=m"(seg[S_DS]),
          [es] "=m"(seg[S_ES]), [fs] "=m"(seg[S_FS]),
          [gs] "=m"(seg[S_GS]), [ss] "=m"(seg[S_SS])
        :
        : "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi",
          "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15",
          "memory"
    );

    printf("rax = 0x%016lx\n", gpr[R_RAX]);
    printf("rbx = 0x%016lx\n", gpr[R_RBX]);
    printf("rcx = 0x%016lx\n", gpr[R_RCX]);
    printf("rdx = 0x%016lx\n", gpr[R_RDX]);
    printf("rsi = 0x%016lx\n", gpr[R_RSI]);
    printf("rdi = 0x%016lx\n", gpr[R_RDI]);
    printf("rbp = 0x%016lx\n", gpr[R_RBP]);
    printf("rsp = 0x%016lx\n", gpr[R_RSP]);
    printf(" r8 = 0x%016lx\n", gpr[R_R8]);
    printf(" r9 = 0x%016lx\n", gpr[R_R9]);
    printf("r10 = 0x%016lx\n", gpr[R_R10]);
    printf("r11 = 0x%016lx\n", gpr[R_R11]);
    printf("r12 = 0x%016lx\n", gpr[R_R12]);
    printf("r13 = 0x%016lx\n", gpr[R_R13]);
    printf("r14 = 0x%016lx\n", gpr[R_R14]);
    printf("r15 = 0x%016lx\n", gpr[R_R15]);
    printf("rip = 0x%016lx\n", gpr[R_RIP]);
    printf("cs = 0x%04x\n", seg[S_CS]);
    printf("ds = 0x%04x\n", seg[S_DS]);
    printf("es = 0x%04x\n", seg[S_ES]);
    printf("fs = 0x%04x\n", seg[S_FS]);
    printf("gs = 0x%04x\n", seg[S_GS]);
    printf("ss = 0x%04x\n", seg[S_SS]);
    printf("rflags = 0x%016lx\n", gpr[R_RFLAGS]);

    return 0;
}

