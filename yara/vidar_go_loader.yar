rule Go_ReflectiveLoader_Decryption_Loop {
    meta:
        description = "Detects the specific Odd/Even decryption loop in a Go-based loader for Vidar"
        author = "Matthieu Gras"
        date = "2025-12-17"

    strings:
        // Standard Go compiler signature
        $go_build_id = "Go build ID: \"" ascii

        $decrypt_loop = {
            31 C0          // xor eax, eax (i = 0)
            EB ??          // jmp short loc_check
            48 FF C0       // inc rax (i++)
            [0-8]          // Alignment NOPs

            // Loop Check: i < len
            48 39 F0       // cmp rax, rsi
            7D ??          // jge loc_exit

            0F B6 14 08    // movzx edx, byte ptr [rax+rcx] (load byte)

            // Parity Check: Is index Odd?
            0F BA E0 00    // bt eax, 0
            72 ??          // jb loc_odd

            // Arithmetic Operation (Even path)
            // Wildcarded constant to catch variants (e.g., add edx, -47)
            83 C2 ??

            88 14 01       // mov [rcx+rax], dl (store byte)
            EB ??          // jmp loc_inc
        }
    
    condition:
        // PE File (MZ) + Go Build ID + Decryption Loop
        uint16(0) == 0x5A4D and
        $go_build_id and
        $decrypt_loop
}