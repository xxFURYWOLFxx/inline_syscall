; Hey there! This is the assembly part of our syscall implementation.
; Huge thanks to @Hxnter999 for helping me out with some of this code!
; This is the assembly part of our syscall implementation.

.code

; This function finds the syscall ID by searching for the "mov eax, <ID>" instruction
; Pretty clever way to get the ID without relying on hardcoded values
GetSyscallId PROC
   push rbx                    ; Save rbx for later - we're gonna need it
   xor rdx, rdx                ; Clear our counter - starting from zero!
   mov rax, rcx                ; Copy our function address to rax so we can scan through it
   mov r8, 20h                 ; We'll look through 32 bytes - should be enough!

_scan:
   cmp rdx, r8                 ; Have we looked at 32 bytes yet?
   jae _fail                   ; If yes, we couldn't find it - time to bail

   mov bl, byte ptr [rax]      ; Grab a byte to check
   cmp bl, 0B8h                ; Is it the 'mov eax' instruction we're looking for? (0xB8)
   je _found                   ; Bingo! We found it!
   
   inc rax                     ; Nope, move to the next byte
   inc rdx                     ; Keep track of how many bytes we've checked
   jmp _scan                   ; Keep looking!

_found:
   ; Sweet! We found the instruction. The next 4 bytes are our syscall ID
   mov eax, dword ptr [rax + 1] ; Grab that ID
   pop rbx                      ; Restore rbx to its original value
   ret                          ; Head back with our syscall ID!

_fail:
   mov eax, -1                  ; Something went wrong, return -1
   pop rbx                      ; Don't forget to restore rbx
   ret                          ; Return with the bad news

GetSyscallId ENDP

; Quick helper function to set up our syscall ID
; Pretty simple - just moves the ID into eax where the syscall instruction expects it
wr_eax PROC
   mov eax, ecx                 ; Move our syscall ID where it needs to be
   ret
wr_eax ENDP

; This is where the magic happens!
; Actually executes our syscall while keeping everything stealthy
syscall_impl PROC
   mov r10, rcx                 ; Windows syscalls need this shadow space thing
   syscall                      ; BAM! Do the syscall
   ret                          ; And we're done!
syscall_impl ENDP

END