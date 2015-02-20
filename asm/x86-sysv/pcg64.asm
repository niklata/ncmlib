format ELF

section '.text' executable align 16

;; uint32_t[4] seed, uint32_t[2] result -> void
align 16
public nk_pcg64_roundfn
nk_pcg64_roundfn:
mov [esp+4], ecx
mov [esp+8], edx
push edi
push esi
sub esp, 32

;; uint64_t xs = os0 ^ os1;
mov eax, [ecx]
xor eax, [ecx+8]
mov [edx], eax
mov eax, [ecx+4]
xor eax, [ecx+12]
mov [edx+4], eax

;; uint64_t r = os1 >> 58;
mov cl, [ecx+15]
shr cl, 2

;;; nk::rotr(xs, r)
cmp cl, 32
je nk_pcg64_roundfn_eq32
ja nk_pcg64_roundfn_gt32
mov edi, [edx]
mov eax, [edx+4]
shrd dword [edx], eax, cl
shrd dword [edx+4], edi, cl
jmp nk_pcg64_roundfn_rshift_done
nk_pcg64_roundfn_gt32:
mov al, cl
mov cl, 64
sub cl, al
mov edi, [edx+4]
mov eax, [edx]
shld dword [edx+4], eax, cl
shld dword [edx], edi, cl
jmp nk_pcg64_roundfn_rshift_done
nk_pcg64_roundfn_eq32:
mov eax, [edx+4]
mov ecx, [edx]
mov [edx], eax
mov eax, ecx
mov [edx+4], eax
nk_pcg64_roundfn_rshift_done:

;; static const uint64_t mc[2] = {4865540595714422341ULL, 2549297995355413924ULL};
;; nk_mul_u128(t, s_, mc);

mov dword [esp+16], 9fccf645h
mov dword [esp+20], 4385df64h
mov dword [esp+24], 1fc65da4h
mov dword [esp+28], 2360ed05h

;; rsp is dst
mov edi, [esp+44] ;; AB
lea esi, [esp+16] ;; CD

;; 0
mov eax, [edi]
mul dword [esi]
mov ecx, edx ; carry
mov [esp], eax

;; 1
mov eax, [edi+4]
mul dword [esi]
add eax, ecx
mov [esp+4], eax ;; HC
adc edx, 0
mov ecx, edx

mov eax, [edi]
mul dword [esi+4]
add [esp+4], eax ;; GD
adc ecx, edx

;; 2
mov eax, [edi+8]
mul dword [esi]
add eax, ecx
mov [esp+8], eax ;; HB
adc edx, 0
mov ecx, edx

mov eax, [edi+4]
mul dword [esi+4]
add [esp+8], eax ;; GC
adc ecx, edx

mov eax, [edi]
mul dword [esi+8]
add [esp+8], eax ;; FD
adc ecx, edx

;; 3
mov eax, [edi+12]
mul dword [esi]
add eax, ecx
mov [esp+12], eax ;; HA

mov eax, [edi+8]
mul dword [esi+4]
add [esp+12], eax ;; GB

mov eax, [edi+4]
mul dword [esi+8]
add [esp+12], eax ;; FC

mov eax, [edi]
mul dword [esi+12]
add [esp+12], eax ;; ED

;; static const uint64_t ac[2] = {1442695040888963407ULL, 6364136223846793005ULL};
;; nk_add_u128(s_, t, ac);

mov ecx, [esp+44] ;; dst

mov eax, [esp]
add eax, 0f767814fh
mov [ecx], eax

mov eax, [esp+4]
adc eax, 14057b7eh
mov [ecx+4], eax

mov eax, [esp+8]
adc eax, 4c957f2dh
mov [ecx+8], eax

mov eax, [esp+12]
adc eax, 5851f42dh
mov [ecx+12], eax

add esp, 32
pop esi
pop edi
ret

