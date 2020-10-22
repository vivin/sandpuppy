        .data
msg:   .asciiz "Hello World"

        .text
        .globl main
main:   li $v0, 4       # syscall 4 (print_str)
        dla $a0, msg     # argument: string (la should be dla for 64 bit?)
        syscall         # print the string
        
        jr $ra          # retrun to caller
