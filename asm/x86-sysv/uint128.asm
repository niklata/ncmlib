format ELF

section '.text' executable align 16

;; uint32_t[4] dst, uint32_t[4] a, uint32_t[4] b -> void
align 16
public nk_add_u128
nk_add_u128:
push esi

mov ecx, [esp+8] ;; dst
mov edx, [esp+12] ;; a
mov esi, [esp+16] ;; b

mov eax, [edx]
add eax, [esi]
mov [ecx], eax

mov eax, [edx+4]
adc eax, [esi+4]
mov [ecx+4], eax

mov eax, [edx+8]
adc eax, [esi+8]
mov [ecx+8], eax

mov eax, [edx+12]
adc eax, [esi+12]
mov [ecx+12], eax

pop esi
ret

;;          A B C D
;;        * E F G H
;;                DH
;;              CH
;;              GD
;;            BH
;;            GC
;;            FD
;;          AH
;;          GB
;;          FC
;;          ED
;;        GA
;;        FB
;;        EC
;;      DA
;;      EB
;;  + EA
;; ----------------
;;
;; 0 = DH
;; 1 = CH + GD + 0_carry
;; 2 = BH + GC + FD + 1_carry
;; 3 = AH + GB + FC + ED + 2_carry

;; uses cdecl convention
;; dst can't alias a or b
;; uint32_t dst[4], uint32_t[4] AB, uint32_t[4] CD -> void
align 16
public nk_mul_u128
nk_mul_u128:
push ebx
push esi
push edi

;; dst = ecx
;; ab[4] = edx
;; cd[4] = esp+16 (on 32b) or r8 (on 64b)

mov ecx, [esp+16] ;; dst
mov edi, [esp+20] ;; AB
mov esi, [esp+24] ;; CD

;; 0
mov eax, [edi]
mul dword [esi]
mov ebx, edx ; carry
mov [ecx], eax

;; 1
mov eax, [edi+4]
mul dword [esi]
add eax, ebx
mov [ecx+4], eax ;; CH
adc edx, 0
mov ebx, edx

mov eax, [edi]
mul dword [esi+4]
add [ecx+4], eax ;; GD
adc ebx, edx

;; 2
mov eax, [edi+8]
mul dword [esi]
add eax, ebx
mov [ecx+8], eax ;; BH
adc edx, 0
mov ebx, edx

mov eax, [edi+4]
mul dword [esi+4]
add [ecx+8], eax ;; GC
adc ebx, edx

mov eax, [edi]
mul dword [esi+8]
add [ecx+8], eax ;; FD
adc ebx, edx

;; 3
mov eax, [edi+12]
mul dword [esi]
add eax, ebx
mov [ecx+12], eax ;; AH

mov eax, [edi+8]
mul dword [esi+4]
add [ecx+12], eax ;; GB

mov eax, [edi+4]
mul dword [esi+8]
add [ecx+12], eax ;; FC

mov eax, [edi]
mul dword [esi+12]
add [ecx+12], eax ;; ED

pop edi
pop esi
pop ebx
ret

;; uint32_t[2] v, uint8_t shift
align 16
public nk_shl_u64
nk_shl_u64:
mov ecx, [esp+8]
mov edx, [esp+4]
and cl, 0x3f
cmp cl, 32
jae @f
mov eax, [edx]
shld dword [edx+4], eax, cl
shl dword [edx], cl
ret
@@:
sub cl, 32
mov eax, [edx]
mov dword [edx], 0
mov [edx+4], eax
shl dword [edx+4], cl
ret

;; uint32_t[2] v, uint8_t shift
align 16
public nk_shr_u64
nk_shr_u64:
mov ecx, [esp+8]
mov edx, [esp+4]
and cl, 0x3f
cmp cl, 32
jae @f
mov eax, [edx+4]
shrd dword [edx], eax, cl
shr dword [edx+4], cl
ret
@@:
sub cl, 32
mov eax, [edx+4]
mov dword [edx+4], 0
mov [edx], eax
shr dword [edx], cl
ret

;; uint32_t[2] v, uint8_t shift
align 16
public nk_rotl_u64
nk_rotl_u64:
mov ecx, [esp+8]
mov edx, [esp+4]
and cl, 0x3f
cmp cl, 32
je nk_rot_u64_eq32
push edi
ja nk_rotl_u64_gt32
mov edi, [edx+4]
mov eax, [edx]
shld dword [edx+4], eax, cl
shld dword [edx], edi, cl
pop edi
ret
nk_rotl_u64_gt32:
mov al, cl
mov cl, 64
sub cl, al
mov edi, [edx]
mov eax, [edx+4]
shrd dword [edx], eax, cl
shrd dword [edx+4], edi, cl
pop edi
ret

;; uint32_t[2] v, uint8_t shift
align 16
public nk_rotr_u64
nk_rotr_u64:
mov ecx, [esp+8]
mov edx, [esp+4]
and cl, 0x3f
cmp cl, 32
je nk_rot_u64_eq32
push edi
ja nk_rotr_u64_gt32
mov edi, [edx]
mov eax, [edx+4]
shrd dword [edx], eax, cl
shrd dword [edx+4], edi, cl
pop edi
ret
nk_rotr_u64_gt32:
mov al, cl
mov cl, 64
sub cl, al
mov edi, [edx+4]
mov eax, [edx]
shld dword [edx+4], eax, cl
shld dword [edx], edi, cl
pop edi
ret
nk_rot_u64_eq32:
mov eax, [edx+4]
mov ecx, [edx]
mov [edx], eax
mov eax, ecx
mov [edx+4], eax
ret

