format ELF64

section '.text' executable align 16

;; uint64_t[2] seed -> uint64_t
align 16
public nk_pcg64_roundfn
nk_pcg64_roundfn:
mov r8, [rdi]
mov r9, [rdi+8]
mov r10, r8
mov rax, r8

mov rcx, r9
xor r10, r9
shr rcx, 58
ror r10, cl

mov r11, 2549297995355413924
mov rdx, 4865540595714422341

imul r11, r8
imul r9, rdx
add r9, r11

mul rdx
add rdx, r9

mov r9, 1442695040888963407
mov r11, 6364136223846793005
add r9, rax
mov rax, r10
adc rdx, r11

mov [rdi], r9
mov [rdi+8], rdx

ret

