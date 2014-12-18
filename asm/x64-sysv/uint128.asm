format ELF64

section '.text' executable align 16

;; argument order is: rdi,rsi,rdx,rcx,r8,r9 :: stack-RTL
;; caller must ensure stack is aligned to 16 bytes
;; callee saves rbx,rsp,rbp,r12-r15

;; uint64_t[2] dst, uint64_t[2] a, uint64_t[2] b -> void
align 16
public nk_add_u128
nk_add_u128:
mov rax, [rsi]
add rax, [rdx]
mov r8, [rsi+8]
adc r8, [rdx+8]
mov [rdi], rax
mov [rdi+8], r8
ret

;; uint64_t[2] dst, uint64_t[2] AB, uint64_t[2] CD -> void
align 16
public nk_mul_u128
nk_mul_u128:
mov r11, [rsi]
mov rax, r11
imul r11, [rdx+8]
mov r10, [rsi+8]
imul r10, [rdx]
add r10, r11
mul qword [rdx]
add rdx, r10
mov [rdi], rax
mov [rdi+8], rdx
ret

