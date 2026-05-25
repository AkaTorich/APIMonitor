; gate_x64.asm - x64 return-capture wrapper gate.
;
; Reached from a per-slot stub (see GenerateTrampoline in iat_hook.c) with
; r10 = slot_id and the stack exactly as the API was called:
;   [rsp] = caller_ret, [rsp+8..32] = home space, [rsp+40] = arg5, ...
;
; Unlike return-address hijacking, this is a real function with a normal
; frame and proper unwind info (FRAME / .allocstack / .pushreg), so x64
; table-based SEH unwinds correctly through it and win32k/WOW64 callbacks
; are unaffected. It logs the CALL, calls the original via a genuine nested
; CALL (forwarding the four register args plus a generous span of stack
; args), captures RAX, optionally logs the RET, and returns.

EXTERN GateLogCall : PROC      ; (slot, regs*, stack*, caller_ret) -> call_id
EXTERN GateWantRet : PROC      ; (slot) -> int
EXTERN GateLogRet  : PROC      ; (slot, caller_ret, call_id, retval)
EXTERN GateOrig    : PROC      ; (slot) -> original fn pointer

.code

PUBLIC ApimonGateX64
ApimonGateX64 PROC FRAME
        push    rbp
        .pushreg rbp
        sub     rsp, 0E0h
        .allocstack 0E0h
        .endprolog

        ; --- frame layout (rsp-relative) ---
        ;  [rsp+0..31]    shadow space for our calls
        ;  [rsp+32..159]  16 outgoing stack args for the original
        ;  [rsp+160]      slot_id
        ;  [rsp+168]      call_id
        ;  [rsp+176]      original fn ptr, then return value
        ;  [rsp+184..216] saved rcx, rdx, r8, r9
        ;  [rsp+232]      caller_ret (entry [rsp])
        ;  [rsp+272]      caller stack args (entry [rsp+40], i.e. arg5)

        mov     qword ptr [rsp+160], r10
        mov     qword ptr [rsp+184], rcx
        mov     qword ptr [rsp+192], rdx
        mov     qword ptr [rsp+200], r8
        mov     qword ptr [rsp+208], r9

        ; GateLogCall(slot, &saved_rcx, &caller_stack, caller_ret)
        mov     rcx, r10
        lea     rdx, [rsp+184]
        lea     r8,  [rsp+272]
        mov     r9,  [rsp+232]
        call    GateLogCall
        mov     qword ptr [rsp+168], rax        ; call_id

        ; copy 16 stack args: [rsp+272 + 8*i] -> [rsp+32 + 8*i]
        xor     r10, r10
copy_args:
        mov     rax, qword ptr [rsp + r10*8 + 272]
        mov     qword ptr [rsp + r10*8 + 32], rax
        inc     r10
        cmp     r10, 16
        jb      copy_args

        ; orig = GateOrig(slot)
        mov     rcx, qword ptr [rsp+160]
        call    GateOrig
        mov     qword ptr [rsp+176], rax        ; original fn ptr

        ; restore the four register args and call the original
        mov     rcx, qword ptr [rsp+184]
        mov     rdx, qword ptr [rsp+192]
        mov     r8,  qword ptr [rsp+200]
        mov     r9,  qword ptr [rsp+208]
        call    qword ptr [rsp+176]
        mov     qword ptr [rsp+176], rax        ; captured return value

        ; want return logged?
        mov     rcx, qword ptr [rsp+160]
        call    GateWantRet
        test    eax, eax
        jz      done

        ; GateLogRet(slot, caller_ret, call_id, retval)
        mov     rcx, qword ptr [rsp+160]
        mov     rdx, qword ptr [rsp+232]
        mov     r8d, dword ptr [rsp+168]
        mov     r9,  qword ptr [rsp+176]
        call    GateLogRet

done:
        mov     rax, qword ptr [rsp+176]        ; return value
        add     rsp, 0E0h
        pop     rbp
        ret
ApimonGateX64 ENDP

END
