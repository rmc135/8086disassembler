#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MEMORY_SIZE 64 * 1024
#define MAX_QUEUE_SIZE 4096

uint8_t read_mem_byte(uint16_t offset);
uint16_t read_mem_word(uint16_t offset);

uint8_t memory[MEMORY_SIZE];
int seg_override = 0;
uint16_t current_cs = 0x1000;  // Default CS for .COM files

// Tracing state
uint8_t is_code[MEMORY_SIZE] = {0};  // Marks if byte is part of code
uint8_t is_start[MEMORY_SIZE] = {0}; // Marks if byte is start of instruction
uint16_t queue[MAX_QUEUE_SIZE];       // Queue for addresses to process
int queue_head = 0;
int queue_tail = 0;

// Register state for tracking
uint8_t ah_value = 0;  // Track value in AH register
uint8_t last_mov_ah = 0; // Track if we recently moved a value to AH

// Control flow types
typedef enum {
    CF_SEQ,     // Sequential execution
    CF_JMP,     // Unconditional jump
    CF_CALL,    // Call
    CF_RET,     // Return
    CF_COND,    // Conditional jump
    CF_JMP_IND, // Indirect jump
    CF_CALL_IND,// Indirect call
    CF_RETF,    // Far return
    CF_JMPF,    // Far jump
    CF_CALLF    // Far call
} cf_type_t;

// Add to queue
void enqueue(uint16_t addr) {
    if ((queue_tail + 1) % MAX_QUEUE_SIZE != queue_head) {
        queue[queue_tail] = addr;
        queue_tail = (queue_tail + 1) % MAX_QUEUE_SIZE;
    }
}

// Get from queue
uint16_t dequeue() {
    if (queue_head == queue_tail) {
        return 0xFFFF;  // Queue empty
    }
    uint16_t addr = queue[queue_head];
    queue_head = (queue_head + 1) % MAX_QUEUE_SIZE;
    return addr;
}

// Get instruction length (improved implementation)
int get_instruction_length(uint16_t ip) {
    uint8_t opcode = read_mem_byte(ip);
    int length = 1; // Start with opcode length
    
    // Handle segment prefixes
    while (opcode == 0x26 || opcode == 0x2E || opcode == 0x36 || opcode == 0x3E) {
        ip++;
        length++;
        opcode = read_mem_byte(ip);
    }
    
    switch (opcode) {
        // Instructions with fixed lengths
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
        case 0xC3: case 0xCB: case 0xCC: case 0xCE: case 0xCF:
        case 0xD4: case 0xD5: case 0xD6: case 0xD7:
        case 0xEC: case 0xED: case 0xEE: case 0xEF:
        case 0xF4: case 0xF5: case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD:
            return length;
            
        // Instructions with 1-byte immediate
        case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C: case 0x34: case 0x3C:
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        case 0xA0: case 0xA2: case 0xA8: case 0xAA: case 0xAC: case 0xAE:
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        case 0xCD: case 0xE0: case 0xE1: case 0xE2: case 0xE3:
        case 0xE4: case 0xE6: case 0xEB:
            return length + 1;
            
        // Instructions with 2-byte immediate
        case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D: case 0x35: case 0x3D:
        case 0xA1: case 0xA3: case 0xA9: case 0xAD: case 0xAF:
        case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        case 0xC2: case 0xCA: case 0xE5: case 0xE7: case 0xE8: case 0xE9:
            return length + 2;
            
        // Far jumps/calls
        case 0x9A: case 0xEA:
            return length + 4;
            
        // Instructions with ModR/M byte
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E:
        case 0xC0: case 0xC1: case 0xC4: case 0xC5: case 0xC6: case 0xC7:
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        case 0xF6: case 0xF7:
        case 0xFE: case 0xFF: {
            // Get ModR/M byte
            uint8_t modrm = read_mem_byte(ip + 1);
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t rm = modrm & 0x07;
            
            // Start with opcode + ModR/M
            int modrm_length = length + 1;
            
            // Calculate additional bytes based on Mod and R/M fields
            if (mod == 0 && rm == 6) { // [disp16]
                modrm_length += 2;
            } else if (mod == 1) { // [reg]+disp8
                modrm_length += 1;
            } else if (mod == 2) { // [reg]+disp16
                modrm_length += 2;
            }
            
            // Special cases for instructions with immediate values
            if (opcode == 0xC6 || opcode == 0xC7) { // MOV r/m, imm
                modrm_length += (opcode == 0xC6) ? 1 : 2; // imm8 or imm16
            } else if (opcode == 0xF6) { // Group 3 r/m8
                uint8_t reg = (modrm >> 3) & 0x07;
                if (reg == 0) { // TEST r/m8, imm8
                    modrm_length += 1;
                }
            } else if (opcode == 0xF7) { // Group 3 r/m16
                uint8_t reg = (modrm >> 3) & 0x07;
                if (reg == 0) { // TEST r/m16, imm16
                    modrm_length += 2;
                }
            } else if (opcode == 0x80 || opcode == 0x81 || opcode == 0x83) { // Group 1
                modrm_length += (opcode == 0x81) ? 2 : 1; // imm16 or imm8
            } else if (opcode == 0xC0 || opcode == 0xC1) { // Group 2 with imm8
                modrm_length += 1;
            }
            
            return modrm_length;
        }
            
        // Group 1A POP r/m16
        case 0x8F: {
            // Get ModR/M byte
            uint8_t modrm = read_mem_byte(ip + 1);
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t rm = modrm & 0x07;
            
            // Start with opcode + ModR/M
            int modrm_length = length + 1;
            
            // Calculate additional bytes based on Mod and R/M fields
            if (mod == 0 && rm == 6) { // [disp16]
                modrm_length += 2;
            } else if (mod == 1) { // [reg]+disp8
                modrm_length += 1;
            } else if (mod == 2) { // [reg]+disp16
                modrm_length += 2;
            }
            
            return modrm_length;
        }
            
        // Default case - minimal handling for other instructions
        default:
            // For instructions we don't explicitly handle, assume 1 byte
            // This is conservative and might miss some instructions
            return length;
    }
}

// Trace instruction to determine control flow
int trace_instruction(uint16_t ip, int *inst_len, cf_type_t *cf_type, uint16_t *target) {
    uint16_t start_ip = ip;
    uint8_t opcode = read_mem_byte(ip++);
    
    // Count segment overrides
    int prefix_count = 0;
    while (opcode == 0x26 || opcode == 0x2E || opcode == 0x36 || opcode == 0x3E) {
        prefix_count++;
        opcode = read_mem_byte(ip++);
    }
    
    // Initialize with sequential flow
    *cf_type = CF_SEQ;
    *target = 0;
    
    // Calculate base instruction length (without prefixes)
    int base_inst_len = 0;
    
    switch (opcode) {
        // Conditional jumps (rel8)
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            base_inst_len = 2; // opcode + rel8
            *cf_type = CF_COND;
            break;
            
        // CALL rel16
        case 0xE8:
            base_inst_len = 3; // opcode + rel16
            *cf_type = CF_CALL;
            break;
            
        // JMP rel16
        case 0xE9:
            base_inst_len = 3; // opcode + rel16
            *cf_type = CF_JMP;
            break;
            
        // JMP rel8
        case 0xEB:
            base_inst_len = 2; // opcode + rel8
            *cf_type = CF_JMP;
            break;
            
        // RET
        case 0xC3:
            base_inst_len = 1;
            *cf_type = CF_RET;
            break;
            
        // RET imm16
        case 0xC2:
            base_inst_len = 3; // opcode + imm16
            *cf_type = CF_RET;
            break;
            
        // RETF
        case 0xCB:
            base_inst_len = 1;
            *cf_type = CF_RETF;
            break;
            
        // RETF imm16
        case 0xCA:
            base_inst_len = 3; // opcode + imm16
            *cf_type = CF_RETF;
            break;
            
        // CALL ptr16:16
        case 0x9A:
            base_inst_len = 5; // opcode + seg:off
            *cf_type = CF_CALLF;
            break;
            
        // JMP ptr16:16
        case 0xEA:
            base_inst_len = 5; // opcode + seg:off
            *cf_type = CF_JMPF;
            break;
            
        // INT
        case 0xCD:
            base_inst_len = 2; // opcode + int_num
            {
                uint8_t int_num = read_mem_byte(start_ip + prefix_count + 1);
                // Only treat INT 21h with AH=4Ch as flow break (terminate program)
                if (int_num == 0x21 && ah_value == 0x4C) {
                    *cf_type = CF_RET; // Treat as flow break
                    ah_value = 0;  // Reset
                }
            }
            break;
            
        // INT 3
        case 0xCC:
            base_inst_len = 1;
            break;
            
        // MOV AH, imm8
        case 0xB4:
            base_inst_len = 2; // opcode + imm8
            ah_value = read_mem_byte(start_ip + prefix_count + 1);
            last_mov_ah = 1;
            break;
            
        // MOV AX, imm16
        case 0xB8:
            base_inst_len = 3; // opcode + imm16
            ah_value = read_mem_byte(start_ip + prefix_count + 2); // AH is the high byte of AX
            last_mov_ah = 1;
            break;
            
        // MOV r/m8, r8 (when destination is AH)
        case 0x88: {
            uint8_t modrm = read_mem_byte(start_ip + prefix_count + 1);
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (modrm == 0xE4 || modrm == 0xE5 || modrm == 0xEC || modrm == 0xED) {
                // MOV AH, r/m8
                base_inst_len = 2;
                // We can't track the exact value without register simulation
                last_mov_ah = 0;
            } else {
                base_inst_len = get_instruction_length(start_ip) - prefix_count;
            }
            break;
        }
            
        // Group 1 operations (ADD, OR, ADC, SBB, AND, SUB, XOR, CMP) with imm8
        case 0x80: {
            uint8_t modrm = read_mem_byte(start_ip + prefix_count + 1);
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t rm = modrm & 0x07;
            
            base_inst_len = 2; // opcode + ModR/M
            
            if (mod == 0 && rm == 6) { // [disp16]
                base_inst_len += 2;
            } else if (mod == 1) { // [reg]+disp8
                base_inst_len += 1;
            } else if (mod == 2) { // [reg]+disp16
                base_inst_len += 2;
            }
            
            base_inst_len += 1; // imm8
            break;
        }
            
        // Group 1 operations with imm16
        case 0x81: {
            uint8_t modrm = read_mem_byte(start_ip + prefix_count + 1);
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t rm = modrm & 0x07;
            
            base_inst_len = 2; // opcode + ModR/M
            
            if (mod == 0 && rm == 6) { // [disp16]
                base_inst_len += 2;
            } else if (mod == 1) { // [reg]+disp8
                base_inst_len += 1;
            } else if (mod == 2) { // [reg]+disp16
                base_inst_len += 2;
            }
            
            base_inst_len += 2; // imm16
            break;
        }
            
        // Group 1 operations with imm8 (sign-extended)
        case 0x83: {
            uint8_t modrm = read_mem_byte(start_ip + prefix_count + 1);
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t rm = modrm & 0x07;
            
            base_inst_len = 2; // opcode + ModR/M
            
            if (mod == 0 && rm == 6) { // [disp16]
                base_inst_len += 2;
            } else if (mod == 1) { // [reg]+disp8
                base_inst_len += 1;
            } else if (mod == 2) { // [reg]+disp16
                base_inst_len += 2;
            }
            
            base_inst_len += 1; // imm8
            break;
        }
            
        // Group 1A POP r/m16
        case 0x8F: {
            uint8_t modrm = read_mem_byte(start_ip + prefix_count + 1);
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t rm = modrm & 0x07;
            
            base_inst_len = 2; // opcode + ModR/M
            
            if (mod == 0 && rm == 6) { // [disp16]
                base_inst_len += 2;
            } else if (mod == 1) { // [reg]+disp8
                base_inst_len += 1;
            } else if (mod == 2) { // [reg]+disp16
                base_inst_len += 2;
            }
            break;
        }
            
        // Most other instructions are sequential
        default:
            base_inst_len = get_instruction_length(start_ip) - prefix_count;
            break;
    }
    
    // Total instruction length includes prefixes
    *inst_len = base_inst_len + prefix_count;
    
    // Calculate target address for jumps and calls
    switch (opcode) {
        // Conditional jumps (rel8)
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            // Target = start_ip + total_instruction_length + offset
            *target = start_ip + *inst_len + (int8_t)read_mem_byte(start_ip + prefix_count + 1);
            break;
            
        // CALL rel16
        case 0xE8:
            // Target = start_ip + total_instruction_length + offset
            *target = start_ip + *inst_len + (int16_t)read_mem_word(start_ip + prefix_count + 1);
            break;
            
        // JMP rel16
        case 0xE9:
            // Target = start_ip + total_instruction_length + offset
            *target = start_ip + *inst_len + (int16_t)read_mem_word(start_ip + prefix_count + 1);
            break;
            
        // JMP rel8
        case 0xEB:
            // Target = start_ip + total_instruction_length + offset
            *target = start_ip + *inst_len + (int8_t)read_mem_byte(start_ip + prefix_count + 1);
            break;
            
        // CALL ptr16:16
        case 0x9A:
            // Target is the offset part of the far pointer
            *target = read_mem_word(start_ip + prefix_count + 1);
            break;
            
        // JMP ptr16:16
        case 0xEA:
            // Target is the offset part of the far pointer
            *target = read_mem_word(start_ip + prefix_count + 1);
            break;
    }
    
    return 0;
}

// Trace code paths
void trace_code(uint16_t start_ip, uint16_t end_ip) {
    // Initialize tracing state
    memset(is_code, 0, sizeof(is_code));
    memset(is_start, 0, sizeof(is_start));
    queue_head = queue_tail = 0;
    
    // Reset register tracking
    ah_value = 0;
    last_mov_ah = 0;
    
    // Start with entry point
    enqueue(start_ip);
    is_code[start_ip] = 1;
    is_start[start_ip] = 1;
    
    while (1) {
        uint16_t ip = dequeue();
        if (ip == 0xFFFF) break; // Queue empty
        
        // Skip if already processed
        if (!is_start[ip]) continue;
        
        // Trace instruction
        int inst_len;
        cf_type_t cf_type;
        uint16_t target;
        
        if (trace_instruction(ip, &inst_len, &cf_type, &target) != 0) {
            // Invalid instruction, skip
            continue;
        }
        
        // Mark instruction bytes as code
        for (int i = 0; i < inst_len; i++) {
            if (ip + i < MEMORY_SIZE) {
                is_code[ip + i] = 1;
            }
        }
        
        // Handle control flow
        switch (cf_type) {
            case CF_SEQ:
                // Sequential execution - add next instruction
                if (ip + inst_len < end_ip && !is_start[ip + inst_len]) {
                    is_start[ip + inst_len] = 1;
                    enqueue(ip + inst_len);
                }
                break;
                
            case CF_JMP:
                // Unconditional jump - add target
                if (target < end_ip && !is_start[target]) {
                    is_start[target] = 1;
                    enqueue(target);
                }
                break;
                
            case CF_CALL:
                // Call - add target and next instruction
                if (target < end_ip && !is_start[target]) {
                    is_start[target] = 1;
                    enqueue(target);
                }
                if (ip + inst_len < end_ip && !is_start[ip + inst_len]) {
                    is_start[ip + inst_len] = 1;
                    enqueue(ip + inst_len);
                }
                break;
                
            case CF_COND:
                // Conditional jump - add target and next instruction
                if (target < end_ip && !is_start[target]) {
                    is_start[target] = 1;
                    enqueue(target);
                }
                if (ip + inst_len < end_ip && !is_start[ip + inst_len]) {
                    is_start[ip + inst_len] = 1;
                    enqueue(ip + inst_len);
                }
                break;
                
            case CF_RET:
            case CF_RETF:
                // Return - don't add anything
                break;
                
            case CF_JMPF:
            case CF_CALLF:
                // Far jump/call - add target
                if (target < end_ip && !is_start[target]) {
                    is_start[target] = 1;
                    enqueue(target);
                }
                break;
                
            case CF_JMP_IND:
            case CF_CALL_IND:
                // Indirect jump/call - can't trace, stop here
                break;
        }
    }
}

// Print data bytes
void print_data(uint16_t addr, int len) {
    // Check if it's a printable string
    int is_string = 1;
    for (int i = 0; i < len; i++) {
        uint8_t b = read_mem_byte(addr + i);
        if (b < 0x20 || b > 0x7E) {
            is_string = 0;
            break;
        }
    }
    
    if (is_string && len > 1) {
        // Print as string
        printf("%04X  ", addr);
        for (int i = 0; i < len && i < 6; i++) {
            printf("%02X ", read_mem_byte(addr + i));
        }
        for (int i = len; i < 6; i++) {
            printf("   ");
        }
        printf("db '");
        for (int i = 0; i < len; i++) {
            putchar(read_mem_byte(addr + i));
        }
        printf("'\n");
    } else {
        // Print as bytes
        for (int i = 0; i < len; i++) {
            uint8_t b = read_mem_byte(addr + i);
            printf("%04X  %02X        db %02X", addr + i, b, b);
            if (isprint(b)) {
                printf(" ; '%c'", b);
            }
            printf("\n");
        }
    }
}

// Original disassembly functions
uint8_t read_mem_byte(uint16_t offset) {
    return memory[offset];
}

uint16_t read_mem_word(uint16_t offset) {
    return read_mem_byte(offset) | (read_mem_byte(offset + 1) << 8);
}

const char* get_segment_override_name() {
    switch (seg_override) {
        case 1: return "ES";
        case 2: return "CS";
        case 3: return "SS";
        case 4: return "DS";
        default: return NULL;
    }
}

const char* get_reg8_name(uint8_t reg) {
    switch (reg) {
        case 0: return "AL";
        case 1: return "CL";
        case 2: return "DL";
        case 3: return "BL";
        case 4: return "AH";
        case 5: return "CH";
        case 6: return "DH";
        case 7: return "BH";
        default: return "??";
    }
}

const char* get_reg16_name(uint8_t reg) {
    switch (reg) {
        case 0: return "AX";
        case 1: return "CX";
        case 2: return "DX";
        case 3: return "BX";
        case 4: return "SP";
        case 5: return "BP";
        case 6: return "SI";
        case 7: return "DI";
        default: return "??";
    }
}

uint16_t calculate_modrm_addr(uint8_t mod, uint8_t rm, uint8_t* inst_bytes, int* inst_len, uint16_t* ip) {
    uint16_t addr = 0;
    
    switch (mod) {
        case 0x00:
            switch (rm) {
                case 0x00: addr = 0; break;  // BX+SI (we don't have register values)
                case 0x01: addr = 0; break;  // BX+DI
                case 0x02: addr = 0; break;  // BP+SI
                case 0x03: addr = 0; break;  // BP+DI
                case 0x04: addr = 0; break;  // SI
                case 0x05: addr = 0; break;  // DI
                case 0x06:
                    addr = read_mem_word(*ip);
                    inst_bytes[(*inst_len)++] = addr & 0xFF;
                    inst_bytes[(*inst_len)++] = addr >> 8;
                    *ip += 2;
                    break;
                case 0x07: addr = 0; break;  // BX
            }
            break;
        case 0x01:
            {
                uint8_t disp = read_mem_byte(*ip);
                inst_bytes[(*inst_len)++] = disp;
                (*ip)++;
                
                switch (rm) {
                    case 0x00: addr = 0; break;  // BX+SI+disp
                    case 0x01: addr = 0; break;  // BX+DI+disp
                    case 0x02: addr = 0; break;  // BP+SI+disp
                    case 0x03: addr = 0; break;  // BP+DI+disp
                    case 0x04: addr = 0; break;  // SI+disp
                    case 0x05: addr = 0; break;  // DI+disp
                    case 0x06: addr = 0; break;  // BP+disp
                    case 0x07: addr = 0; break;  // BX+disp
                }
            }
            break;
        case 0x02:
            {
                uint16_t disp = read_mem_word(*ip);
                inst_bytes[(*inst_len)++] = disp & 0xFF;
                inst_bytes[(*inst_len)++] = disp >> 8;
                *ip += 2;
                
                switch (rm) {
                    case 0x00: addr = 0; break;  // BX+SI+disp
                    case 0x01: addr = 0; break;  // BX+DI+disp
                    case 0x02: addr = 0; break;  // BP+SI+disp
                    case 0x03: addr = 0; break;  // BP+DI+disp
                    case 0x04: addr = 0; break;  // SI+disp
                    case 0x05: addr = 0; break;  // DI+disp
                    case 0x06: addr = 0; break;  // BP+disp
                    case 0x07: addr = 0; break;  // BX+disp
                }
            }
            break;
    }
    
    return addr;
}

void format_modrm_addr(char* buf, uint8_t mod, uint8_t rm, uint8_t* inst_bytes, int inst_len) {
    switch (mod) {
        case 0x00:
            switch (rm) {
                case 0x00: strcpy(buf, "[BX+SI]"); break;
                case 0x01: strcpy(buf, "[BX+DI]"); break;
                case 0x02: strcpy(buf, "[BP+SI]"); break;
                case 0x03: strcpy(buf, "[BP+DI]"); break;
                case 0x04: strcpy(buf, "[SI]"); break;
                case 0x05: strcpy(buf, "[DI]"); break;
                case 0x06:
                    {
                        uint16_t addr = *(uint16_t*)(inst_bytes + inst_len - 2);
                        sprintf(buf, "[%04X]", addr);
                    }
                    break;
                case 0x07: strcpy(buf, "[BX]"); break;
            }
            break;
        case 0x01:
            {
                uint8_t disp = *(uint8_t*)(inst_bytes + inst_len - 1);
                switch (rm) {
                    case 0x00: sprintf(buf, "[BX+SI%+d]", (int8_t)disp); break;
                    case 0x01: sprintf(buf, "[BX+DI%+d]", (int8_t)disp); break;
                    case 0x02: sprintf(buf, "[BP+SI%+d]", (int8_t)disp); break;
                    case 0x03: sprintf(buf, "[BP+DI%+d]", (int8_t)disp); break;
                    case 0x04: sprintf(buf, "[SI%+d]", (int8_t)disp); break;
                    case 0x05: sprintf(buf, "[DI%+d]", (int8_t)disp); break;
                    case 0x06: sprintf(buf, "[BP%+d]", (int8_t)disp); break;
                    case 0x07: sprintf(buf, "[BX%+d]", (int8_t)disp); break;
                }
            }
            break;
        case 0x02:
            {
                uint16_t disp = *(uint16_t*)(inst_bytes + inst_len - 2);
                switch (rm) {
                    case 0x00: sprintf(buf, "[BX+SI%+d]", (int16_t)disp); break;
                    case 0x01: sprintf(buf, "[BX+DI%+d]", (int16_t)disp); break;
                    case 0x02: sprintf(buf, "[BP+SI%+d]", (int16_t)disp); break;
                    case 0x03: sprintf(buf, "[BP+DI%+d]", (int16_t)disp); break;
                    case 0x04: sprintf(buf, "[SI%+d]", (int16_t)disp); break;
                    case 0x05: sprintf(buf, "[DI%+d]", (int16_t)disp); break;
                    case 0x06: sprintf(buf, "[BP%+d]", (int16_t)disp); break;
                    case 0x07: sprintf(buf, "[BX%+d]", (int16_t)disp); break;
                }
            }
            break;
    }
}

int disassemble_instruction(uint16_t start_ip) {
    uint16_t ip = start_ip;
    
    uint8_t inst_bytes[6] = {0};
    int inst_len = 0;
    char mnemonic[128] = "UNKNOWN";
    
    seg_override = 0;
    uint8_t opcode = read_mem_byte(ip);
    
    // Check for segment override prefixes
    int has_seg_override = 0;
    uint16_t seg_override_ip = ip;
    uint8_t seg_override_byte = 0;
    while (opcode == 0x26 || opcode == 0x2E || opcode == 0x36 || opcode == 0x3E) {
        // Set segment override
        switch (opcode) {
            case 0x26: seg_override = 1; break; // ES
            case 0x2E: seg_override = 2; break; // CS
            case 0x36: seg_override = 3; break; // SS
            case 0x3E: seg_override = 4; break; // DS
        }
        seg_override_byte = opcode;
        ip++;
        opcode = read_mem_byte(ip);
        has_seg_override = 1;
        break;  // Only handle one segment override prefix
    }
    
    // If we have a segment override, print it on its own line
    if (has_seg_override) {
        const char* seg_name = get_segment_override_name();
        printf("%04X  %02X                %s:\n", seg_override_ip, seg_override_byte, seg_name);
    }
    
    inst_bytes[inst_len++] = opcode;
    ip++;
    
    switch (opcode) {
        case 0x02: { // ADD r8, r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "ADD %s,%s", 
                        get_reg8_name(reg), get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "ADD %s,%s", 
                        get_reg8_name(reg), addr_buf);
            }
            break;
        }
        case 0x03: { // ADD r16, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "ADD %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "ADD %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0x04: // ADD AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "ADD AL,%02X", inst_bytes[1]);
            break;
        case 0x05: { // ADD AX, imm16
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "ADD AX,%04X", imm);
            break;
        }
        case 0x08: { // OR r/m8, r8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "OR %s,%s", 
                        get_reg8_name(rm), get_reg8_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "OR %s,%s", 
                        addr_buf, get_reg8_name(reg));
            }
            break;
        }
        case 0x09: { // OR r/m16, r16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "OR %s,%s", 
                        get_reg16_name(rm), get_reg16_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "OR %s,%s", 
                        addr_buf, get_reg16_name(reg));
            }
            break;
        }
        case 0x0A: { // OR r8, r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "OR %s,%s", 
                        get_reg8_name(reg), get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "OR %s,%s", 
                        get_reg8_name(reg), addr_buf);
            }
            break;
        }
        case 0x0B: { // OR r16, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "OR %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "OR %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0x0C: // OR AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "OR AL,%02X", inst_bytes[1]);
            break;
        case 0x0D: { // OR AX, imm16
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "OR AX,%04X", imm);
            break;
        }
        case 0x10: { // ADC r/m8, r8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "ADC %s,%s", 
                        get_reg8_name(rm), get_reg8_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "ADC %s,%s", 
                        addr_buf, get_reg8_name(reg));
            }
            break;
        }
        case 0x13: { // ADC r16, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "ADC %s,%s", 
                        get_reg16_name(rm), get_reg16_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "ADC %s,%s", 
                        addr_buf, get_reg16_name(reg));
            }
            break;
        }
        case 0x14: // ADC AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "ADC AL,%02X", inst_bytes[1]);
            break;
        case 0x15: { // ADC AX, imm16
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "ADC AX,%04X", imm);
            break;
        }
        case 0x1A: { // SBB r8, r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "SBB %s,%s", 
                        get_reg8_name(reg), get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "SBB %s,%s", 
                        get_reg8_name(reg), addr_buf);
            }
            break;
        }
        case 0x1B: { // SBB r16, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "SBB %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "SBB %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0x1C: // SBB AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "SBB AL,%02X", inst_bytes[1]);
            break;
        case 0x1D: { // SBB AX, imm16
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "SBB AX,%04X", imm);
            break;
        }
        case 0x20: { // AND r/m8, r8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "AND %s,%s", 
                        get_reg8_name(rm), get_reg8_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "AND %s,%s", 
                        addr_buf, get_reg8_name(reg));
            }
            break;
        }
        case 0x21: { // AND r/m16, r16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "AND %s,%s", 
                        get_reg16_name(rm), get_reg16_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "AND %s,%s", 
                        addr_buf, get_reg16_name(reg));
            }
            break;
        }
        case 0x22: { // AND r8, r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "AND %s,%s", 
                        get_reg8_name(reg), get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "AND %s,%s", 
                        get_reg8_name(reg), addr_buf);
            }
            break;
        }
        case 0x23: { // AND r16, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "AND %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "AND %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0x24: // AND AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "AND AL,%02X", inst_bytes[1]);
            break;
        case 0x25: { // AND AX, imm16
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "AND AX,%04X", imm);
            break;
        }
        case 0x27: // DAA
            snprintf(mnemonic, sizeof(mnemonic), "DAA");
            break;
        case 0x28: { // SUB r/m8, r8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "SUB %s,%s", 
                        get_reg8_name(rm), get_reg8_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "SUB %s,%s", 
                        addr_buf, get_reg8_name(reg));
            }
            break;
        }
        case 0x29: { // SUB r/m16, r16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "SUB %s,%s", 
                        get_reg16_name(rm), get_reg16_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "SUB %s,%s", 
                        addr_buf, get_reg16_name(reg));
            }
            break;
        }
        case 0x2A: { // SUB r8, r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "SUB %s,%s", 
                        get_reg8_name(reg), get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "SUB %s,%s", 
                        get_reg8_name(reg), addr_buf);
            }
            break;
        }
        case 0x2B: { // SUB r16, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "SUB %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "SUB %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0x2C: // SUB AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "SUB AL,%02X", inst_bytes[1]);
            break;
        case 0x2D: { // SUB AX, imm16
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "SUB AX,%04X", imm);
            break;
        }
        case 0x2F: // DAS
            snprintf(mnemonic, sizeof(mnemonic), "DAS");
            break;
        case 0x30: { // XOR r/m8, r8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "XOR %s,%s", 
                        get_reg8_name(rm), get_reg8_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "XOR %s,%s", 
                        addr_buf, get_reg8_name(reg));
            }
            break;
        }
        case 0x31: { // XOR r/m16, r16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "XOR %s,%s", 
                        get_reg16_name(rm), get_reg16_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "XOR %s,%s", 
                        addr_buf, get_reg16_name(reg));
            }
            break;
        }
        case 0x32: { // XOR r8, r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "XOR %s,%s", 
                        get_reg8_name(reg), get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "XOR %s,%s", 
                        get_reg8_name(reg), addr_buf);
            }
            break;
        }
        case 0x33: { // XOR r16, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "XOR %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "XOR %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0x34: // XOR AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "XOR AL,%02X", inst_bytes[1]);
            break;
        case 0x35: { // XOR AX, imm16
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "XOR AX,%04X", imm);
            break;
        }
        case 0x37: // AAA
            snprintf(mnemonic, sizeof(mnemonic), "AAA");
            break;
        case 0x38: { // CMP r/m8, r8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "CMP %s,%s", 
                        get_reg8_name(rm), get_reg8_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "CMP %s,%s", 
                        addr_buf, get_reg8_name(reg));
            }
            break;
        }
        case 0x39: { // CMP r/m16, r16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "CMP %s,%s", 
                        get_reg16_name(rm), get_reg16_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "CMP %s,%s", 
                        addr_buf, get_reg16_name(reg));
            }
            break;
        }
        case 0x3A: { // CMP r8, r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "CMP %s,%s", 
                        get_reg8_name(reg), get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "CMP %s,%s", 
                        get_reg8_name(reg), addr_buf);
            }
            break;
        }
        case 0x3B: { // CMP r16, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "CMP %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "CMP %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0x3C: // CMP AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "CMP AL,%02X", inst_bytes[1]);
            break;
        case 0x3D: { // CMP AX, imm16
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "CMP AX,%04X", imm);
            break;
        }
        case 0x3F: // AAS
            snprintf(mnemonic, sizeof(mnemonic), "AAS");
            break;
        case 0x40: // INC AX
            snprintf(mnemonic, sizeof(mnemonic), "INC AX");
            break;
        case 0x41: // INC CX
            snprintf(mnemonic, sizeof(mnemonic), "INC CX");
            break;
        case 0x42: // INC DX
            snprintf(mnemonic, sizeof(mnemonic), "INC DX");
            break;
        case 0x43: // INC BX
            snprintf(mnemonic, sizeof(mnemonic), "INC BX");
            break;
        case 0x44: // INC SP
            snprintf(mnemonic, sizeof(mnemonic), "INC SP");
            break;
        case 0x45: // INC BP
            snprintf(mnemonic, sizeof(mnemonic), "INC BP");
            break;
        case 0x46: // INC SI
            snprintf(mnemonic, sizeof(mnemonic), "INC SI");
            break;
        case 0x47: // INC DI
            snprintf(mnemonic, sizeof(mnemonic), "INC DI");
            break;
        case 0x48: // DEC AX
            snprintf(mnemonic, sizeof(mnemonic), "DEC AX");
            break;
        case 0x49: // DEC CX
            snprintf(mnemonic, sizeof(mnemonic), "DEC CX");
            break;
        case 0x4A: // DEC DX
            snprintf(mnemonic, sizeof(mnemonic), "DEC DX");
            break;
        case 0x4B: // DEC BX
            snprintf(mnemonic, sizeof(mnemonic), "DEC BX");
            break;
        case 0x4C: // DEC SP
            snprintf(mnemonic, sizeof(mnemonic), "DEC SP");
            break;
        case 0x4D: // DEC BP
            snprintf(mnemonic, sizeof(mnemonic), "DEC BP");
            break;
        case 0x4E: // DEC SI
            snprintf(mnemonic, sizeof(mnemonic), "DEC SI");
            break;
        case 0x4F: // DEC DI
            snprintf(mnemonic, sizeof(mnemonic), "DEC DI");
            break;
        case 0x50: // PUSH AX
            snprintf(mnemonic, sizeof(mnemonic), "PUSH AX");
            break;
        case 0x51: // PUSH CX
            snprintf(mnemonic, sizeof(mnemonic), "PUSH CX");
            break;
        case 0x52: // PUSH DX
            snprintf(mnemonic, sizeof(mnemonic), "PUSH DX");
            break;
        case 0x53: // PUSH BX
            snprintf(mnemonic, sizeof(mnemonic), "PUSH BX");
            break;
        case 0x54: // PUSH SP
            snprintf(mnemonic, sizeof(mnemonic), "PUSH SP");
            break;
        case 0x55: // PUSH BP
            snprintf(mnemonic, sizeof(mnemonic), "PUSH BP");
            break;
        case 0x56: // PUSH SI
            snprintf(mnemonic, sizeof(mnemonic), "PUSH SI");
            break;
        case 0x57: // PUSH DI
            snprintf(mnemonic, sizeof(mnemonic), "PUSH DI");
            break;
        case 0x58: // POP AX
            snprintf(mnemonic, sizeof(mnemonic), "POP AX");
            break;
        case 0x59: // POP CX
            snprintf(mnemonic, sizeof(mnemonic), "POP CX");
            break;
        case 0x5A: // POP DX
            snprintf(mnemonic, sizeof(mnemonic), "POP DX");
            break;
        case 0x5B: // POP BX
            snprintf(mnemonic, sizeof(mnemonic), "POP BX");
            break;
        case 0x5C: // POP SP
            snprintf(mnemonic, sizeof(mnemonic), "POP SP");
            break;
        case 0x5D: // POP BP
            snprintf(mnemonic, sizeof(mnemonic), "POP BP");
            break;
        case 0x5E: // POP SI
            snprintf(mnemonic, sizeof(mnemonic), "POP SI");
            break;
        case 0x5F: // POP DI
            snprintf(mnemonic, sizeof(mnemonic), "POP DI");
            break;
        case 0x60: // PUSHA (80186+)
            snprintf(mnemonic, sizeof(mnemonic), "PUSHA");
            break;
        case 0x61: // POPA (80186+)
            snprintf(mnemonic, sizeof(mnemonic), "POPA");
            break;
        case 0x68: // PUSH imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "PUSH %04X", imm);
            }
            break;
        case 0x69: // IMUL r16, r/m16, imm16
            {
                uint8_t modrm = read_mem_byte(ip);
                inst_bytes[inst_len++] = modrm;
                ip++;
                
                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t reg = (modrm >> 3) & 0x07;
                uint8_t rm = modrm & 0x07;
                
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                
                if (mod == 0x03) { // Register mode
                    snprintf(mnemonic, sizeof(mnemonic), "IMUL %s,%s,%04X", 
                            get_reg16_name(reg), get_reg16_name(rm), imm);
                } else { // Memory operand mode
                    uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                    char addr_buf[32];
                    format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                    snprintf(mnemonic, sizeof(mnemonic), "IMUL %s,%s,%04X", 
                            get_reg16_name(reg), addr_buf, imm);
                }
                break;
            }
        case 0x6A: // PUSH imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "PUSH %02X", inst_bytes[1]);
            break;
        case 0x6B: // IMUL r16, r/m16, imm8
            {
                uint8_t modrm = read_mem_byte(ip);
                inst_bytes[inst_len++] = modrm;
                ip++;
                
                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t reg = (modrm >> 3) & 0x07;
                uint8_t rm = modrm & 0x07;
                
                uint8_t imm = read_mem_byte(ip);
                inst_bytes[inst_len++] = imm;
                ip++;
                
                if (mod == 0x03) { // Register mode
                    snprintf(mnemonic, sizeof(mnemonic), "IMUL %s,%s,%02X", 
                            get_reg16_name(reg), get_reg16_name(rm), imm);
                } else { // Memory operand mode
                    uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                    char addr_buf[32];
                    format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                    snprintf(mnemonic, sizeof(mnemonic), "IMUL %s,%s,%02X", 
                            get_reg16_name(reg), addr_buf, imm);
                }
                break;
            }
        case 0x70: { // JO rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JO %04X", target);
            break;
        }
        case 0x71: { // JNO rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JNO %04X", target);
            break;
        }
        case 0x72: { // JB/JC/JNAE rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JB %04X", target);
            break;
        }
        case 0x73: { // JNB/JNC/JAE rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JNB %04X", target);
            break;
        }
        case 0x74: { // JZ/JE rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JZ %04X", target);
            break;
        }
        case 0x75: { // JNZ/JNE rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JNZ %04X", target);
            break;
        }
        case 0x76: { // JBE/JNA rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JBE %04X", target);
            break;
        }
        case 0x77: { // JNBE/JA rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JA %04X", target);
            break;
        }
        case 0x78: { // JS rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JS %04X", target);
            break;
        }
        case 0x79: { // JNS rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JNS %04X", target);
            break;
        }
        case 0x7A: { // JP/JPE rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JP %04X", target);
            break;
        }
        case 0x7B: { // JNP/JPO rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JNP %04X", target);
            break;
        }
        case 0x7C: { // JL/JNGE rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JL %04X", target);
            break;
        }
        case 0x7D: { // JNL/JGE rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JGE %04X", target);
            break;
        }
        case 0x7E: { // JLE/JNG rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JLE %04X", target);
            break;
        }
        case 0x7F: { // JNLE/JG rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JG %04X", target);
            break;
        }
        case 0x80: { // Group 1 operations on r/m8 with imm8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            uint8_t imm = read_mem_byte(ip);
            inst_bytes[inst_len++] = imm;
            ip++;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "ADD"; break;
                case 1: op = "OR"; break;
                case 2: op = "ADC"; break;
                case 3: op = "SBB"; break;
                case 4: op = "AND"; break;
                case 5: op = "SUB"; break;
                case 6: op = "XOR"; break;
                case 7: op = "CMP"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,%02X", 
                        op, get_reg8_name(rm), imm);
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,%02X", 
                        op, addr_buf, imm);
            }
            break;
        }
        case 0x81: { // Group 1 operations on r/m16 with imm16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "ADD"; break;
                case 1: op = "OR"; break;
                case 2: op = "ADC"; break;
                case 3: op = "SBB"; break;
                case 4: op = "AND"; break;
                case 5: op = "SUB"; break;
                case 6: op = "XOR"; break;
                case 7: op = "CMP"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,%04X", 
                        op, get_reg16_name(rm), imm);
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,%04X", 
                        op, addr_buf, imm);
            }
            break;
        }
        case 0x83: { // Group 1 operations on r/m16 with imm8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            uint8_t imm = read_mem_byte(ip);
            inst_bytes[inst_len++] = imm;
            ip++;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "ADD"; break;
                case 1: op = "OR"; break;
                case 2: op = "ADC"; break;
                case 3: op = "SBB"; break;
                case 4: op = "AND"; break;
                case 5: op = "SUB"; break;
                case 6: op = "XOR"; break;
                case 7: op = "CMP"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,%02X", 
                        op, get_reg16_name(rm), imm);
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,%02X", 
                        op, addr_buf, imm);
            }
            break;
        }
        case 0x84: { // TEST r/m8, r8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "TEST %s,%s", 
                        get_reg8_name(rm), get_reg8_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "TEST %s,%s", 
                        addr_buf, get_reg8_name(reg));
            }
            break;
        }
        case 0x85: { // TEST r/m16, r16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "TEST %s,%s", 
                        get_reg16_name(rm), get_reg16_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "TEST %s,%s", 
                        addr_buf, get_reg16_name(reg));
            }
            break;
        }
        case 0x86: { // XCHG r8, r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "XCHG %s,%s", 
                        get_reg8_name(reg), get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "XCHG %s,%s", 
                        get_reg8_name(reg), addr_buf);
            }
            break;
        }
        case 0x87: { // XCHG r16, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "XCHG %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "XCHG %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0x88: { // MOV r/m8, r8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        get_reg8_name(rm), get_reg8_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        addr_buf, get_reg8_name(reg));
            }
            break;
        }
        case 0x89: { // MOV r/m16, r16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        get_reg16_name(rm), get_reg16_name(reg));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        addr_buf, get_reg16_name(reg));
            }
            break;
        }
        case 0x8A: { // MOV r8, r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        get_reg8_name(reg), get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        get_reg8_name(reg), addr_buf);
            }
            break;
        }
        case 0x8B: { // MOV r16, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0x8C: { // MOV r/m16, Sreg
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            const char* sreg = "";
            switch (reg) {
                case 0: sreg = "ES"; break;
                case 1: sreg = "CS"; break;
                case 2: sreg = "SS"; break;
                case 3: sreg = "DS"; break;
                default: sreg = "??"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        get_reg16_name(rm), sreg);
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        addr_buf, sreg);
            }
            break;
        }
        case 0x8D: { // LEA r16, m
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
            char addr_buf[32];
            format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
            snprintf(mnemonic, sizeof(mnemonic), "LEA %s,%s", 
                    get_reg16_name(reg), addr_buf);
            break;
        }
        case 0x8E: { // MOV Sreg, r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            const char* sreg = "";
            switch (reg) {
                case 0: sreg = "ES"; break;
                case 1: sreg = "CS"; break;
                case 2: sreg = "SS"; break;
                case 3: sreg = "DS"; break;
                default: sreg = "??"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        sreg, get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%s", 
                        sreg, addr_buf);
            }
            break;
        }
        case 0x8F: { // Group 1A POP r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            // Only reg=0 is defined for POP
            if (reg == 0) {
                if (mod == 0x03) { // Register mode
                    snprintf(mnemonic, sizeof(mnemonic), "POP %s", 
                            get_reg16_name(rm));
                } else { // Memory operand mode
                    uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                    char addr_buf[32];
                    format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                    snprintf(mnemonic, sizeof(mnemonic), "POP %s", 
                            addr_buf);
                }
            } else {
                // Undefined operation
                snprintf(mnemonic, sizeof(mnemonic), "db %02X", opcode);
            }
            break;
        }
        case 0x90: // NOP
            snprintf(mnemonic, sizeof(mnemonic), "NOP");
            break;
        case 0x91: // XCHG AX, CX
            snprintf(mnemonic, sizeof(mnemonic), "XCHG AX,CX");
            break;
        case 0x92: // XCHG AX, DX
            snprintf(mnemonic, sizeof(mnemonic), "XCHG AX,DX");
            break;
        case 0x93: // XCHG AX, BX
            snprintf(mnemonic, sizeof(mnemonic), "XCHG AX,BX");
            break;
        case 0x94: // XCHG AX, SP
            snprintf(mnemonic, sizeof(mnemonic), "XCHG AX,SP");
            break;
        case 0x95: // XCHG AX, BP
            snprintf(mnemonic, sizeof(mnemonic), "XCHG AX,BP");
            break;
        case 0x96: // XCHG AX, SI
            snprintf(mnemonic, sizeof(mnemonic), "XCHG AX,SI");
            break;
        case 0x97: // XCHG AX, DI
            snprintf(mnemonic, sizeof(mnemonic), "XCHG AX,DI");
            break;
        case 0x98: // CBW
            snprintf(mnemonic, sizeof(mnemonic), "CBW");
            break;
        case 0x99: // CWD
            snprintf(mnemonic, sizeof(mnemonic), "CWD");
            break;
        case 0x9A: // CALL ptr16:16
            inst_bytes[inst_len++] = read_mem_byte(ip);
            inst_bytes[inst_len++] = read_mem_byte(ip + 1);
            inst_bytes[inst_len++] = read_mem_byte(ip + 2);
            inst_bytes[inst_len++] = read_mem_byte(ip + 3);
            ip += 4;
            snprintf(mnemonic, sizeof(mnemonic), "CALL %04X:%04X", 
                    *(uint16_t*)(inst_bytes + 3), *(uint16_t*)(inst_bytes + 1));
            break;
        case 0x9B: // WAIT
            snprintf(mnemonic, sizeof(mnemonic), "WAIT");
            break;
        case 0x9C: // PUSHF
            snprintf(mnemonic, sizeof(mnemonic), "PUSHF");
            break;
        case 0x9D: // POPF
            snprintf(mnemonic, sizeof(mnemonic), "POPF");
            break;
        case 0x9E: // SAHF
            snprintf(mnemonic, sizeof(mnemonic), "SAHF");
            break;
        case 0x9F: // LAHF
            snprintf(mnemonic, sizeof(mnemonic), "LAHF");
            break;
        case 0xA0: // MOV AL, [addr16]
            inst_bytes[inst_len++] = read_mem_byte(ip);
            inst_bytes[inst_len++] = read_mem_byte(ip + 1);
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "MOV AL,[%04X]", 
                    *(uint16_t*)(inst_bytes + 1));
            break;
        case 0xA1: // MOV AX, [addr16]
            inst_bytes[inst_len++] = read_mem_byte(ip);
            inst_bytes[inst_len++] = read_mem_byte(ip + 1);
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "MOV AX,[%04X]", 
                    *(uint16_t*)(inst_bytes + 1));
            break;
        case 0xA2: // MOV [addr16], AL
            inst_bytes[inst_len++] = read_mem_byte(ip);
            inst_bytes[inst_len++] = read_mem_byte(ip + 1);
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "MOV [%04X],AL", 
                    *(uint16_t*)(inst_bytes + 1));
            break;
        case 0xA3: // MOV [addr16], AX
            inst_bytes[inst_len++] = read_mem_byte(ip);
            inst_bytes[inst_len++] = read_mem_byte(ip + 1);
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "MOV [%04X],AX", 
                    *(uint16_t*)(inst_bytes + 1));
            break;
        case 0xA4: // MOVSB
            snprintf(mnemonic, sizeof(mnemonic), "MOVSB");
            break;
        case 0xA5: // MOVSW
            snprintf(mnemonic, sizeof(mnemonic), "MOVSW");
            break;
        case 0xA6: // CMPSB
            snprintf(mnemonic, sizeof(mnemonic), "CMPSB");
            break;
        case 0xA7: // CMPSW
            snprintf(mnemonic, sizeof(mnemonic), "CMPSW");
            break;
        case 0xA8: // TEST AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "TEST AL,%02X", inst_bytes[1]);
            break;
        case 0xA9: { // TEST AX, imm16
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            snprintf(mnemonic, sizeof(mnemonic), "TEST AX,%04X", imm);
            break;
        }
        case 0xAA: // STOSB
            snprintf(mnemonic, sizeof(mnemonic), "STOSB");
            break;
        case 0xAB: // STOSW
            snprintf(mnemonic, sizeof(mnemonic), "STOSW");
            break;
        case 0xAC: // LODSB
            snprintf(mnemonic, sizeof(mnemonic), "LODSB");
            break;
        case 0xAD: // LODSW
            snprintf(mnemonic, sizeof(mnemonic), "LODSW");
            break;
        case 0xAE: // SCASB
            snprintf(mnemonic, sizeof(mnemonic), "SCASB");
            break;
        case 0xAF: // SCASW
            snprintf(mnemonic, sizeof(mnemonic), "SCASW");
            break;
        case 0xB0: // MOV AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "MOV AL,%02X", inst_bytes[1]);
            break;
        case 0xB1: // MOV CL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "MOV CL,%02X", inst_bytes[1]);
            break;
        case 0xB2: // MOV DL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "MOV DL,%02X", inst_bytes[1]);
            break;
        case 0xB3: // MOV BL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "MOV BL,%02X", inst_bytes[1]);
            break;
        case 0xB4: // MOV AH, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "MOV AH,%02X", inst_bytes[1]);
            break;
        case 0xB5: // MOV CH, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "MOV CH,%02X", inst_bytes[1]);
            break;
        case 0xB6: // MOV DH, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "MOV DH,%02X", inst_bytes[1]);
            break;
        case 0xB7: // MOV BH, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "MOV BH,%02X", inst_bytes[1]);
            break;
        case 0xB8: // MOV AX, imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "MOV AX,%04X", imm);
            }
            break;
        case 0xB9: // MOV CX, imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "MOV CX,%04X", imm);
            }
            break;
        case 0xBA: // MOV DX, imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "MOV DX,%04X", imm);
            }
            break;
        case 0xBB: // MOV BX, imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "MOV BX,%04X", imm);
            }
            break;
        case 0xBC: // MOV SP, imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "MOV SP,%04X", imm);
            }
            break;
        case 0xBD: // MOV BP, imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "MOV BP,%04X", imm);
            }
            break;
        case 0xBE: // MOV SI, imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "MOV SI,%04X", imm);
            }
            break;
        case 0xBF: // MOV DI, imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "MOV DI,%04X", imm);
            }
            break;
        case 0xC0: { // Group 2 operations on r/m8 with imm8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            uint8_t imm = read_mem_byte(ip);
            inst_bytes[inst_len++] = imm;
            ip++;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "ROL"; break;
                case 1: op = "ROR"; break;
                case 2: op = "RCL"; break;
                case 3: op = "RCR"; break;
                case 4: op = "SHL"; break;
                case 5: op = "SHR"; break;
                case 6: op = "SHL"; break; // Same as 4
                case 7: op = "SAR"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,%02X", 
                        op, get_reg8_name(rm), imm);
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,%02X", 
                        op, addr_buf, imm);
            }
            break;
        }
        case 0xC1: { // Group 2 operations on r/m16 with imm8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            uint8_t imm = read_mem_byte(ip);
            inst_bytes[inst_len++] = imm;
            ip++;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "ROL"; break;
                case 1: op = "ROR"; break;
                case 2: op = "RCL"; break;
                case 3: op = "RCR"; break;
                case 4: op = "SHL"; break;
                case 5: op = "SHR"; break;
                case 6: op = "SHL"; break; // Same as 4
                case 7: op = "SAR"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,%02X", 
                        op, get_reg16_name(rm), imm);
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,%02X", 
                        op, addr_buf, imm);
            }
            break;
        }
        case 0xC2: // RET imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "RET %04X", imm);
            }
            break;
        case 0xC3: // RET
            snprintf(mnemonic, sizeof(mnemonic), "RET");
            break;
        case 0xC4: { // LES r16, m
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "LES %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "LES %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0xC5: { // LDS r16, m
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "LDS %s,%s", 
                        get_reg16_name(reg), get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "LDS %s,%s", 
                        get_reg16_name(reg), addr_buf);
            }
            break;
        }
        case 0xC6: { // MOV r/m8, imm8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            uint8_t imm = read_mem_byte(ip);
            inst_bytes[inst_len++] = imm;
            ip++;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%02X", 
                        get_reg8_name(rm), imm);
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%02X", 
                        addr_buf, imm);
            }
            break;
        }
        case 0xC7: { // MOV r/m16, imm16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            uint16_t imm = read_mem_word(ip);
            inst_bytes[inst_len++] = imm & 0xFF;
            inst_bytes[inst_len++] = imm >> 8;
            ip += 2;
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%04X", 
                        get_reg16_name(rm), imm);
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "MOV %s,%04X", 
                        addr_buf, imm);
            }
            break;
        }
        case 0xC8: // ENTER imm16, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            inst_bytes[inst_len++] = read_mem_byte(ip + 1);
            inst_bytes[inst_len++] = read_mem_byte(ip + 2);
            ip += 3;
            snprintf(mnemonic, sizeof(mnemonic), "ENTER %04X,%02X", 
                    *(uint16_t*)(inst_bytes + 1), inst_bytes[3]);
            break;
        case 0xC9: // LEAVE
            snprintf(mnemonic, sizeof(mnemonic), "LEAVE");
            break;
        case 0xCA: // RETF imm16
            {
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                snprintf(mnemonic, sizeof(mnemonic), "RETF %04X", imm);
            }
            break;
        case 0xCB: // RETF
            snprintf(mnemonic, sizeof(mnemonic), "RETF");
            break;
        case 0xCC: // INT 3
            snprintf(mnemonic, sizeof(mnemonic), "INT 3");
            break;
        case 0xCD: { // INT
            uint8_t int_num = read_mem_byte(ip);
            inst_bytes[inst_len++] = int_num;
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "INT %02X", int_num);
            break;
        }
        case 0xCE: // INTO
            snprintf(mnemonic, sizeof(mnemonic), "INTO");
            break;
        case 0xCF: // IRET
            snprintf(mnemonic, sizeof(mnemonic), "IRET");
            break;
        case 0xD0: { // Group 2 operations on r/m8 with 1
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "ROL"; break;
                case 1: op = "ROR"; break;
                case 2: op = "RCL"; break;
                case 3: op = "RCR"; break;
                case 4: op = "SHL"; break;
                case 5: op = "SHR"; break;
                case 6: op = "SHL"; break; // Same as 4
                case 7: op = "SAR"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,1", 
                        op, get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,1", 
                        op, addr_buf);
            }
            break;
        }
        case 0xD1: { // Group 2 operations on r/m16 with 1
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "ROL"; break;
                case 1: op = "ROR"; break;
                case 2: op = "RCL"; break;
                case 3: op = "RCR"; break;
                case 4: op = "SHL"; break;
                case 5: op = "SHR"; break;
                case 6: op = "SHL"; break; // Same as 4
                case 7: op = "SAR"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,1", 
                        op, get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,1", 
                        op, addr_buf);
            }
            break;
        }
        case 0xD2: { // Group 2 operations on r/m8 with CL
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "ROL"; break;
                case 1: op = "ROR"; break;
                case 2: op = "RCL"; break;
                case 3: op = "RCR"; break;
                case 4: op = "SHL"; break;
                case 5: op = "SHR"; break;
                case 6: op = "SHL"; break; // Same as 4
                case 7: op = "SAR"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,CL", 
                        op, get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,CL", 
                        op, addr_buf);
            }
            break;
        }
        case 0xD3: { // Group 2 operations on r/m16 with CL
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "ROL"; break;
                case 1: op = "ROR"; break;
                case 2: op = "RCL"; break;
                case 3: op = "RCR"; break;
                case 4: op = "SHL"; break;
                case 5: op = "SHR"; break;
                case 6: op = "SHL"; break; // Same as 4
                case 7: op = "SAR"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,CL", 
                        op, get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s,CL", 
                        op, addr_buf);
            }
            break;
        }
        case 0xD4: // AAM
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "AAM %02X", inst_bytes[1]);
            break;
        case 0xD5: // AAD
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "AAD %02X", inst_bytes[1]);
            break;
        case 0xD6: // SALC
            snprintf(mnemonic, sizeof(mnemonic), "SALC");
            break;
        case 0xD7: // XLAT
            snprintf(mnemonic, sizeof(mnemonic), "XLAT");
            break;
        case 0xD8: // ESC (FPU instruction)
        case 0xD9:
        case 0xDA:
        case 0xDB:
        case 0xDC:
        case 0xDD:
        case 0xDE:
        case 0xDF:
            {
                uint8_t modrm = read_mem_byte(ip);
                inst_bytes[inst_len++] = modrm;
                ip++;
                
                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t reg = (modrm >> 3) & 0x07;
                uint8_t rm = modrm & 0x07;
                
                if (mod == 0x03) { // Register mode
                    snprintf(mnemonic, sizeof(mnemonic), "ESC %02X,%s", 
                            opcode - 0xD8, get_reg16_name(rm));
                } else { // Memory operand mode
                    uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                    char addr_buf[32];
                    format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                    snprintf(mnemonic, sizeof(mnemonic), "ESC %02X,%s", 
                            opcode - 0xD8, addr_buf);
                }
                break;
            }
        case 0xE0: // LOOPNE rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "LOOPNE %02X", inst_bytes[1]);
            break;
        case 0xE1: // LOOPE rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "LOOPE %02X", inst_bytes[1]);
            break;
        case 0xE2: // LOOP rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "LOOP %02X", inst_bytes[1]);
            break;
        case 0xE3: // JCXZ rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "JCXZ %02X", inst_bytes[1]);
            break;
        case 0xE4: // IN AL, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "IN AL,%02X", inst_bytes[1]);
            break;
        case 0xE5: // IN AX, imm8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "IN AX,%02X", inst_bytes[1]);
            break;
        case 0xE6: // OUT imm8, AL
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "OUT %02X,AL", inst_bytes[1]);
            break;
        case 0xE7: // OUT imm8, AX
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            snprintf(mnemonic, sizeof(mnemonic), "OUT %02X,AX", inst_bytes[1]);
            break;
        case 0xE8: { // CALL rel16
            uint16_t offset = read_mem_word(ip);
            inst_bytes[inst_len++] = offset & 0xFF;
            inst_bytes[inst_len++] = offset >> 8;
            ip += 2;
            // Calculate target: start_ip + 3 (instruction length) + (int16_t)offset
            uint16_t target = start_ip + 3 + (int16_t)offset;
            snprintf(mnemonic, sizeof(mnemonic), "CALL %04X", target);
            break;
        }
        case 0xE9: { // JMP rel16
            uint16_t offset = read_mem_word(ip);
            inst_bytes[inst_len++] = offset & 0xFF;
            inst_bytes[inst_len++] = offset >> 8;
            ip += 2;
            // Calculate target: start_ip + 3 (instruction length) + (int16_t)offset
            uint16_t target = start_ip + 3 + (int16_t)offset;
            snprintf(mnemonic, sizeof(mnemonic), "JMP %04X", target);
            break;
        }
        case 0xEA: // JMP ptr16:16
            inst_bytes[inst_len++] = read_mem_byte(ip);
            inst_bytes[inst_len++] = read_mem_byte(ip + 1);
            inst_bytes[inst_len++] = read_mem_byte(ip + 2);
            inst_bytes[inst_len++] = read_mem_byte(ip + 3);
            ip += 4;
            snprintf(mnemonic, sizeof(mnemonic), "JMP %04X:%04X", 
                    *(uint16_t*)(inst_bytes + 3), *(uint16_t*)(inst_bytes + 1));
            break;
        case 0xEB: { // JMP rel8
            inst_bytes[inst_len++] = read_mem_byte(ip);
            ip++;
            // Calculate target address: start_ip + 2 (instruction length) + (int8_t)offset
            uint16_t target = start_ip + 2 + (int8_t)inst_bytes[1];
            snprintf(mnemonic, sizeof(mnemonic), "JMP %04X", target);
            break;
        }
        case 0xEC: // IN AL, DX
            snprintf(mnemonic, sizeof(mnemonic), "IN AL,DX");
            break;
        case 0xED: // IN AX, DX
            snprintf(mnemonic, sizeof(mnemonic), "IN AX,DX");
            break;
        case 0xEE: // OUT DX, AL
            snprintf(mnemonic, sizeof(mnemonic), "OUT DX,AL");
            break;
        case 0xEF: // OUT DX, AX
            snprintf(mnemonic, sizeof(mnemonic), "OUT DX,AX");
            break;
        case 0xF0: // LOCK
            snprintf(mnemonic, sizeof(mnemonic), "LOCK");
            break;
        case 0xF2: // REPNZ
            snprintf(mnemonic, sizeof(mnemonic), "REPNZ");
            break;
        case 0xF3: // REP/REPZ
            snprintf(mnemonic, sizeof(mnemonic), "REP");
            break;
        case 0xF4: // HLT
            snprintf(mnemonic, sizeof(mnemonic), "HLT");
            break;
        case 0xF5: // CMC
            snprintf(mnemonic, sizeof(mnemonic), "CMC");
            break;
        case 0xF8: // CLC
            snprintf(mnemonic, sizeof(mnemonic), "CLC");
            break;
        case 0xF9: // STC
            snprintf(mnemonic, sizeof(mnemonic), "STC");
            break;
        case 0xFA: // CLI
            snprintf(mnemonic, sizeof(mnemonic), "CLI");
            break;
        case 0xFB: // STI
            snprintf(mnemonic, sizeof(mnemonic), "STI");
            break;
        case 0xFC: // CLD
            snprintf(mnemonic, sizeof(mnemonic), "CLD");
            break;
        case 0xFD: // STD
            snprintf(mnemonic, sizeof(mnemonic), "STD");
            break;
        case 0xF6: { // Group 3 operations on r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "TEST"; break;
                case 1: // Undefined
                case 2: op = "NOT"; break;
                case 3: op = "NEG"; break;
                case 4: op = "MUL"; break;
                case 5: op = "IMUL"; break;
                case 6: op = "DIV"; break;
                case 7: op = "IDIV"; break;
            }
            
            if (reg == 0) { // TEST
                uint8_t imm = read_mem_byte(ip);
                inst_bytes[inst_len++] = imm;
                ip++;
                
                if (mod == 0x03) { // Register mode
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s,%02X", 
                            op, get_reg8_name(rm), imm);
                } else { // Memory operand mode
                    uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                    char addr_buf[32];
                    format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s,%02X", 
                            op, addr_buf, imm);
                }
            } else if (reg == 1) { // Undefined
                snprintf(mnemonic, sizeof(mnemonic), "UNDEFINED");
            } else {
                if (mod == 0x03) { // Register mode
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s", 
                            op, get_reg8_name(rm));
                } else { // Memory operand mode
                    uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                    char addr_buf[32];
                    format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s", 
                            op, addr_buf);
                }
            }
            break;
        }
        case 0xF7: { // Group 3 operations on r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "TEST"; break;
                case 1: // Undefined
                case 2: op = "NOT"; break;
                case 3: op = "NEG"; break;
                case 4: op = "MUL"; break;
                case 5: op = "IMUL"; break;
                case 6: op = "DIV"; break;
                case 7: op = "IDIV"; break;
            }
            
            if (reg == 0) { // TEST
                uint16_t imm = read_mem_word(ip);
                inst_bytes[inst_len++] = imm & 0xFF;
                inst_bytes[inst_len++] = imm >> 8;
                ip += 2;
                
                if (mod == 0x03) { // Register mode
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s,%04X", 
                            op, get_reg16_name(rm), imm);
                } else { // Memory operand mode
                    uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                    char addr_buf[32];
                    format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s,%04X", 
                            op, addr_buf, imm);
                }
            } else if (reg == 1) { // Undefined
                snprintf(mnemonic, sizeof(mnemonic), "UNDEFINED");
            } else {
                if (mod == 0x03) { // Register mode
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s", 
                            op, get_reg16_name(rm));
                } else { // Memory operand mode
                    uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                    char addr_buf[32];
                    format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s", 
                            op, addr_buf);
                }
            }
            break;
        }
        case 0xFE: { // Group 4 operations on r/m8
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "INC"; break;
                case 1: op = "DEC"; break;
                default: op = "UNDEFINED"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s", 
                        op, get_reg8_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s", 
                        op, addr_buf);
            }
            break;
        }
        case 0xFF: { // Group 5 operations on r/m16
            uint8_t modrm = read_mem_byte(ip);
            inst_bytes[inst_len++] = modrm;
            ip++;
            
            uint8_t mod = (modrm >> 6) & 0x03;
            uint8_t reg = (modrm >> 3) & 0x07;
            uint8_t rm = modrm & 0x07;
            
            const char* op = "";
            switch (reg) {
                case 0: op = "INC"; break;
                case 1: op = "DEC"; break;
                case 2: op = "CALL"; break;
                case 3: op = "CALLF"; break;
                case 4: op = "JMP"; break;
                case 5: op = "JMPF"; break;
                case 6: op = "PUSH"; break;
                default: op = "UNDEFINED"; break;
            }
            
            if (mod == 0x03) { // Register mode
                snprintf(mnemonic, sizeof(mnemonic), "%s %s", 
                        op, get_reg16_name(rm));
            } else { // Memory operand mode
                uint16_t addr = calculate_modrm_addr(mod, rm, inst_bytes, &inst_len, &ip);
                char addr_buf[32];
                format_modrm_addr(addr_buf, mod, rm, inst_bytes, inst_len);
                snprintf(mnemonic, sizeof(mnemonic), "%s %s", 
                        op, addr_buf);
            }
            break;
        }
        default:
            // Add ASCII comment for printable characters
            if (isprint(opcode)) {
                snprintf(mnemonic, sizeof(mnemonic), "db %02X ; '%c'", opcode, opcode);
            } else {
                snprintf(mnemonic, sizeof(mnemonic), "db %02X", opcode);
            }
            break;
    }
    
    // Format the output
    printf("%04X  ", start_ip + (has_seg_override ? 1 : 0));  // Adjust IP if we printed a segment override
    
    // Print instruction bytes
    for (int i = 0; i < inst_len; i++) {
        printf("%02X ", inst_bytes[i]);
    }
    
    // Pad with spaces if instruction is shorter than 6 bytes
    for (int i = inst_len; i < 6; i++) {
        printf("   ");
    }
    
    // Print mnemonic
    printf("%s\n", mnemonic);
    
    seg_override = 0;
    
    // Return the total instruction length (segment override + main instruction)
    return (has_seg_override ? 1 : 0) + inst_len;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s filename.com\n", argv[0]);
        return 1;
    }
    
    const char* filename = argv[1];
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return 1;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size > 0xFF00) {
        printf("File too large\n");
        fclose(file);
        return 1;
    }
    
    memset(memory, 0, MEMORY_SIZE);
    
    // Load .COM file at offset 0x100 (flat memory model)
    fread(memory + 0x100, 1, file_size, file);
    fclose(file);
    
    // Trace code paths
    uint16_t start_ip = 0x100;
    uint16_t end_ip = 0x100 + file_size;
    trace_code(start_ip, end_ip);
    
    // Disassemble code and print data
    uint16_t ip = start_ip;
    while (ip < end_ip) {
        if (is_start[ip]) {
            // Disassemble instruction
            int inst_len = disassemble_instruction(ip);
            ip += inst_len;
        } else {
            // Find contiguous data region
            int data_len = 1;
            while (ip + data_len < end_ip && !is_code[ip + data_len]) {
                data_len++;
            }
            
            // Print data
            print_data(ip, data_len);
            ip += data_len;
        }
    }
    
    return 0;
}
