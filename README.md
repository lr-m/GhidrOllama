<p align="center">

  <img src="https://github.com/luke-r-m/GhidrOllama/assets/47477832/c21b75ab-f186-4a2b-8206-15c1c1d5218b" width="200">

</p>

<p align="center">
  
  <img src="https://github.com/luke-r-m/GhidrOllama/assets/47477832/59e1b7e2-6331-4968-ac07-4b5ceded673b" width="400">

</p>

**Ollama API interaction Ghidra script for LLM-assisted reverse-engineering.**

## What is this?

This script interacts with Ollama's API to interact with Large Language Models (LLMs). It utilizes the Ollama API to perform various reverse engineering tasks without leaving Ghidra. It supports both local and remote instances of Ollama. This script is inspired by [GptHidra](https://github.com/evyatar9/GptHidra).

## Prerequisites

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Ollama](https://github.com/jmorganca/ollama)
- [Any of the Ollama models](https://ollama.ai/library)

### Ollama Setup

Feel free to replace `llama3.1:8b` with any model from the collection of [Ollama Models](https://ollama.ai/library)

```
curl -fsSL https://ollama.com/install.sh | sh
ollama run llama3.1:8b
```

Now you should be good to go, `localhost:11434` should be ready to handle requests

*Note:* This script also supports remote instances, set the IP address and port during first configuration.

## Usage

1. Place the *GhidrOllama.py* script and the *ghidrollama_utils* directory in your Ghidra script directory (usually `~/ghidra_scripts`).
2. Find a function/instruction you want to feed to the LLM
3. Run the script from the Script Manager window
4. If this is the first time running the script, complete the initial configuration (this can be changed later)
5. Select how you want to function/instruction to be analysed
6. Wait until the output is printed to the console (wait time varies depending on model and specifications of host)

## What can it do?

1. Explain the function that is currently in the decompiler window
2. Suggest a name for the current function, will automatically name the function if this has been enabled
3. Rewrite current function with recommended comments
4. Completely rewrite the current function, trying to improve function/parameter/variable names and also add comments
5. User can ask a question about a function
6. Find bugs/suggest potential vulnerabilities in current function (more just to make sure you've covered everything, some suggestions are dumb as it doesn't have the context)
7. Use a modified version of this [LeafBlowerLeafFunctions.py Ghidra Script](https://github.com/grayhatacademy/ghidra_scripts) to automate analysis of potential 'leaf' functions such as *strcpy*, *memcpy*, *strlen*, etc in binaries with stripped symbols, auto rename if this is enabled
8. Explain the single assembly instruction that is currently selected in the listing window
9. Explain multiple assembly instructions that are currently selected in the listing window
10. General prompt entry for asking questions (rather than having to Google, good for simple stuff)

## Configuration Options

The following config options are available, and can be configured on first run:
- *Server IP* : If using remote instance, set to IP of remote instance, otherwise enter `localhost`
- *Port* : If your instance is on a different port, change it here - default is `11434`
- *Scheme* : Select `http` or `https` depending on how your instance is configured
- *Model* : Select the model you wish to use for analysis, you can change this at any point
- *Project-specific prompt* : Used to give some additional context to the model if this is required
- *Response Comments* : Some options store the responses as a comment at the top of the function, this can be enabled/disabled here
- *Auto-renaming* : Some options try and automatically rename functions based on the responses, this can be enabled/disabled here

Options 11 & 12 can be used to adjust settings after first-run.

## Notes

- It is worth noting that the analysis will only be as good as the model, this script basically just bridges the models and Ghidra
- The better the model (more parameters, slower) the more comprehensive and correct the analysis will be (most of the time!)
- If you want a quick overview of a function, *llama3.1:8b* is quick and gives a decent analysis
- Be careful with large functions and low-context models, if the function is too big for the context window, the model will respond with complete gibberish (if it responds at all)

## Function Analysis Examples

Below is an implementation of *strchr()* as seen in Ghidra decompile window with stripped symbols:

```c
char * FUN_801a7490(char *param_1,char param_2)

{
  char cVar1;
  char *pcVar2;
  
  cVar1 = *param_1;
  if (cVar1 == '\0') {
    pcVar2 = (char *)0x0;
  }
  else {
    pcVar2 = (char *)0x0;
    do {
      if (param_2 == cVar1) {
        pcVar2 = param_1;
      }
      param_1 = param_1 + 1;
      cVar1 = *param_1;
    } while (cVar1 != '\0');
  }
  if (param_2 != '\0') {
    param_1 = pcVar2;
  }
  return param_1;
}
```

The following analysis was performed using the *llama3.1:8b* model.

### Option 1 - Function Summary

> Interesting function! As a reverse engineer assistant, I'll break down what this code does and provide some insights.
>
> **Function Signature**
> 
> `char * FUN_801a7490(char *param_1,char param_2)`
> 
> The function takes two parameters:
> 
> * `param_1`: a pointer to a character array ( likely a string)
> * `param_2`: a single character
> 
> **Function Body**
> 
> The function does the following:
> 
> 1. It checks if the first character of `param_1` (`cVar1`) is `\0`. If it is, then `pcVar2` is set to `(char *)0x0`, which is essentially NULL.
> 2. If `cVar1` is not `\0`, it enters a loop where:
> 	* It checks if the character `param_2` matches the current character in `param_1` (`cVar1`). If they match, then `pcVar2` is set to the address of `param_1`.
> 	* The pointer `param_1` is incremented by one to point to the next character in the string.
> 	* The loop continues until the end of the string is reached (i.e., `cVar1` becomes `\0`).
> 3. If `param_2` is not null, then the function returns the address stored in `pcVar2`.
> 
> **Insights**
> 
> Based on this code, it appears to be searching for a character (`param_2`) within a string (`param_1`). The search stops as soon as it finds the first occurrence of that character.
> 
> The `if (param_2 != '\0') { param_1 = pcVar2; }` statement suggests that if `param_2` is found in the string, the function returns a pointer to that location within the string. If not, it still returns a valid pointer ( likely pointing to the  beginning of the string).

### Option 2 - Function Naming

GhidrOllama renamed the function to `find_char_in_string`

### Option 3 - Add Comments

> Here is the modified function with additional comments to explain its behavior:
> ```c
> char * FUN_801a7490(char *param_1, char param_2)
> {
>   // Initialize a character variable (cVar1) to hold the first character of param_1.
>   char cVar1;
>   
>   // Initialize a pointer variable (pcVar2) to point to null initially.
>   char *pcVar2;
>   
>   // Assign the first character of param_1 to cVar1. This will be used as a starting point for searching in the string.
>   cVar1 = *param_1;
>   
>   // Check if the input string (param_1) is empty ('\0').
>   if (cVar1 == '\0') {
>     // If it's empty, set pcVar2 to null, effectively indicating that no match was found.
>     pcVar2 = (char *)0x0;
>   }
>   else {
>     // Initialize pcVar2 to null, which will be updated later if a match is found.
>     pcVar2 = (char *)0x0;
>     
>     // Loop through the string param_1 until we reach its end ('\0').
>     do {
>       // Check if the current character (cVar1) matches the input parameter (param_2).
>       if (param_2 == cVar1) {
>         // If it's a match, update pcVar2 to point to the beginning of param_1, effectively returning its address.
>         pcVar2 = param_1;
>       }
>       
>       // Move on to the next character in param_1 by incrementing its pointer (param_1 = param_1 + 1).
>       param_1 = param_1 + 1;
>       
>       // Update cVar1 to hold the new current character.
>       cVar1 = *param_1;
>     } while (cVar1 != '\0');
>   }
>   
>   // Check if a match was found by verifying that param_2 is not null ('\0').
>   if (param_2 != '\0') {
>     // If it's not null, update param_1 to point to the matched string in pcVar2.
>     param_1 = pcVar2;
>   }
>   
>   // Return the address of the matched string or an empty string if no match was found.
>   return param_1;
> }
> ```
> This function appears to be searching for a single character (param_2) within a string (param_1). It returns the address of the matched string, or null if no match is found. If the input string is empty, it returns null immediately.

### Option 4 - Rewrite Function

> Here is the rewritten function with more descriptive names and comments:
> 
> ```c
> /**
>  * Find the index of a given character in a string.
>  *
>  * @param str The input string to search in.
>  * @param charToFind The character to find in the string.
>  *
>  * @return A pointer to the found character in the string, or NULL if not found.
>  */
> char* findCharacterInString(char* str, char charToFind)
> {
>     // Initialize variables
>     char currentChar;
>     char* foundCharPtr;
> 
>     // Check if the input string is empty
>     currentChar = *str;
>     if (currentChar == '\0') {
>         // If the string is empty, return NULL
>         foundCharPtr = NULL;
>     } else {
>         // Initialize pointer to point to end of string
>         foundCharPtr = NULL;
> 
>         // Loop through each character in the string
>         do {
>             // Check if current character matches the character to find
>             if (charToFind == currentChar) {
>                 // If a match is found, update the pointer and break out of loop
>                 foundCharPtr = str;
>                 break;
>             }
> 
>             // Move to next character in string
>             str++;
>             currentChar = *str;
>         } while (currentChar != '\0');
>     }
> 
>     // Ensure that if charToFind is not empty, we return the pointer to the found character
>     if (charToFind != '\0') {
>         str = foundCharPtr;
>     }
> 
>     // Return the pointer to the found character, or NULL if not found
>     return str;
> }
> ```
> 
> Note that I've used a more descriptive function name `findCharacterInString` and added comments to explain what each part of the code is doing. I've also used more descriptive variable names like `currentChar`, `foundCharPtr`, `str` instead of `cVar1`, `pcVar2`, etc.

## Vulnerability Search Example

I gave GhidrOllama some code that I know contains a stack overflow to see if it spots it, and here is the response:

> Interesting areas that may present security vulnerabilities in the given code snippet:
> 
> 1. **NULL Pointer Dereference**: In the function `upnp_device_discovery`, there is a possibility of NULL pointer dereference when accessing `iVar2` at offset `0x2910`. This can happen if `DAT_8025d514` is less than 3, and `*(int *)(param_1 + 0x2910)` returns NULL. To fix this, add a check to ensure that `iVar2` is not NULL before dereferencing it.
> 
>     ```c
>     if (DAT_8025d514 < 3 && iVar2 != NULL) {
>       iVar2 = *(int *)(param_1 + 0x2910);
>     }
>     ```
> 
> 2. **Buffer Overflow**: In the function `upnp_device_discovery`, there is a possibility of buffer overflow when calling `strcpy(auStack_98, iVar2 + 5);`. This can happen if `iVar2` plus 5 exceeds the bounds of the `auStack_98` array. To fix this, add checks to ensure that the source and destination buffers are not too large for the target string.
> 
>     ```c
>     if (iVar2 != NULL && iVar2 + 5 <= iVar1) {
>         strcpy(auStack_98, iVar2 + 5);
>     }
>     ```
> 
> 3. **Use-After-Free**: In the function `upnp_device_discovery`, there is a possibility of use-after-free when accessing `iVar1` after it has been freed in the following code snippet:
> 
>     ```c
>     iVar1 = FUN_801a6bb4(iVar2,s_urn_schemas_wifialliance_org_dev_801eb090,0x24);
>     if (iVar1 == 0) {
>       iVar2 = iVar2 + 0x24;
>       iVar1 = FUN_801a7114(iVar2,s_check_pse_fid_Q7__801d0030 + 0x10);
>     }
>     ```
> 
>    The `iVar1` is freed in the line where it's assigned to `FUN_801a7114`, but then it's still being used as an argument in the following line. To fix this, reassign the result of `FUN_801a7114` back to `iVar1`.
> 
>     ```c
>     iVar1 = FUN_801a7114(iVar2,s_check_pse_fid_Q7__801d0030 + 0x10);
>     ```
> 
> 4. **SQL Injection**: In the function `upnp_device_discovery`, there is a possibility of SQL injection when calling `FUN_801a6bb4` with user input as an argument. To fix this, use parameterized queries or prepared statements to prevent SQL injection.
> 
>     ```c
>     iVar1 = FUN_801a6bb4(iVar2,s_check_pse_fid_Q7__801d0030 + 0x10);
>     ```
>
> These are some of the potential security vulnerabilities that can be found in the given code snippet.

We can see it has found the stack overflow in point 2, in the other points, it seems to make assumptions about behaviour that are completely incorrect.

## Describe Instruction Example

The script can also provide descriptions of instructions in the listing window (saves browsing programmers manuals), here is an example for that:

```
movz v1, a0, v0
```

Here is the response:

> A delightful MIPS instruction!
>
> The instruction `movz v1, a0, v0` is a load/store instruction that performs an integer move with zero-extend operation.
>
> Let's break it down:
> 
> * `movz`: This is the mnemonic for the instruction, which stands for "move with zero-extend". It's used to transfer data between registers while extending sign bits.
> * `v1`, `a0`, and `v0` are register names. In MIPS, these registers have the following roles:
> 	+ `v1`: Destination register (where the result will be stored).
> 	+ `a0`: Source register 1 (contains the value to be moved).
> 	+ `v0`: Source register 2 is not necessary in this case.
> 
> The purpose of this instruction is to copy the contents of `a0` into `v1`, and extend the sign bit of `a0` if it's negative. The result will be stored in `v1`.
> 
> To understand what "zero-extend" means, let's consider an example:
> 
> Suppose `a0` contains the value `-5`. In binary representation, this is `11111011`. When we perform a zero-extend operation on this value, we essentially add leading zeros to make it a 32-bit integer. The resulting binary value would be `00000000011111011`.
> 
> In assembly code examples:
> 
> 1. Suppose you have the following values in registers:
> 	* `a0`: -5 (binary: `11111011`)
> 	* `v0` is not used in this example
> 	Then, after executing `movz v1, a0, v0`, the register `v1` will contain the value `-5`.
> 
> 2. Now suppose you have:
> 	* `a0`: 17 (binary: `00010001`)
> 	* Again, `v0` is not used
> 
> After running `movz v1, a0, v0`, the register `v1` will still hold the original binary value of `17`, since it's already positive and doesn't require any zero-extension.
> 
> 3. One more example with:
> 	* `a0`: -128 (binary: `10000000`)
> 	* Again, `v0` is not used
> 
> After executing `movz v1, a0, v0`, the register `v1` will contain the value `-128`.
> 
> Remember that in MIPS, the instruction `movz` can only move between registers of the same size (32-bit integers). The values are transferred directly without any conversion or promotion.
>
> In summary, `movz v1, a0, v0` is used to copy integer data from one register (`a0`) to another (`v1`), extending sign bits if necessary.

## Describe Assembly Example

I asked the model to explain the following assembly:

```
  801a7490 00 00 82 80     lb         v0,0x0(a0)
  801a7494 00 2e 05 00     sll        a1,a1,0x18
  801a7498 0b 00 40 10     beq        v0,zero,LAB_801a74c8
  801a749c 03 2e 05 00     _sra       a1,a1,0x18
  801a74a0 21 18 00 00     clear      v1
                        LAB_801a74a4                                    XREF[1]:     801a74b4(j)  
  801a74a4 26 10 a2 00     xor        v0,a1,v0
  801a74a8 0a 18 82 00     movz       v1,a0,v0
  801a74ac 01 00 84 24     addiu      a0,a0,0x1
  801a74b0 00 00 82 80     lb         v0,0x0(a0)
  801a74b4 fb ff 40 14     bne        v0,zero,LAB_801a74a4
  801a74b8 00 00 00 00     _nop
                        LAB_801a74bc                                    XREF[1]:     801a74c8(j)  
  801a74bc 21 10 80 00     move       v0,a0
  801a74c0 08 00 e0 03     jr         ra
  801a74c4 0b 10 65 00     _movn      v0,v1,a1
                        LAB_801a74c8                                    XREF[1]:     801a7498(j)  
  801a74c8 2f 9d 06 08     j          LAB_801a74bc
  801a74cc 21 18 00 00     _clear     v1
```

Here is the response:

> A MIPS assembly code snippet!
> 
> Here's a breakdown of what each instruction does:
> 
> **0x801a7490: lb v0,0x0(a0)**
> 
> * `lb` is the "load byte" instruction.
> * `v0` is the destination register (i.e., where the result will be stored).
> * `0x0(a0)` is the effective address of the byte to be loaded. The `(a0)` part means that the value in register `a0` should be added to the immediate value `0x0` to form the effective address.
> * So, this instruction loads a byte from memory location `a0 + 0 = a0` into register `v0`.
> 
> **0x801a7494: sll a1,a1,0x18**
> 
> * `sll` is the "shift left logical" instruction.
> * `a1` is the source register (i.e., the value to be shifted).
> * The immediate value `0x18` specifies how many bits to shift. In this case, it's 24 bits (since MIPS uses 32-bit words), so all bits are effectively zeroed out.
> * So, this instruction clears the upper bits of register `a1`.
> 
> **0x801a7498: beq v0,zero,0x801a74c8**
> 
> * `beq` is the "branch if equal" instruction.
> * The first two operands are compared. If they're equal (i.e., both zero), then...
> * ...the program branches to the address specified by the third operand: **0x801a74c8**.
> 
> **0x801a749c: _sra a1,a1,0x18**
> 
> * This instruction is similar to `sll`, but it's "shift right arithmetic". The effect is the same as in the previous instruction.
> 
> **0x801a74a0: clear v1**
> 
> * `_clear` (note the underscore) clears the value of register `v1`.
> 
> **0x801a74a4: xor v0,a1,v0**
> 
> * `xor` is the "exclusive OR" instruction.
> * The first two operands are compared. If either bit is set in one operand but not both, then...
> * ...the corresponding bit in the result (register `v0`) is set.
> 
> **0x801a74a8: movz v1,a0,v0**
> 
> * `_movz` (note the underscore) loads a word from memory location `a0 + 0 = a0` into register `v1`.
> 
> **0x801a74ac: addiu a0,a0,0x1**
> 
> * `addiu` is the "add immediate unsigned" instruction.
> * The value in register `a0` is incremented by 1.
> 
> **0x801a74b0: lb v0,0x0(a0)**
> 
> * This is similar to the first instruction. It loads a byte from memory location `a0 + 0 = a0` into register `v0`.
> 
> **0x801a74b4: bne v0,zero,0x801a74a4**
> 
> * `bne` is the "branch if not equal" instruction.
> * The value in register `v0` is compared to zero. If they're not equal (i.e., `v0` is non-zero), then...
> * ...the program branches back to **0x801a74a4**.
> 
> **0x801a74b8: _nop**
> 
> * `_nop` is a no-op instruction, which has no effect.
> 
> **0x801a74bc: move v0,a0**
> 
> * `move` loads the value of register `a0` into register `v0`.
> 
> **0x801a74c0: jr ra**
> 
> * `jr` is the "jump register" instruction.
> * The program jumps to the address stored in register `ra`. This is likely the return address, so the function will terminate.
> 
> **0x801a74c4: _movn v0,v1,a1**
> 
> * `_movn` loads a word from memory location `a1 + 0 = a1` into register `v0`.
> 
> **0x801a74c8: j 0x801a74bc**
> 
> * This is the branch target of the first `beq` instruction.
> * The program branches to **0x801a74bc**.
> 
> **0x801a74cc: _clear v1**
> 
> * `_clear` clears the value of register `v1`.
> 
> The code seems to be implementing some kind of loop, incrementing a counter (`a0`) and doing some computation based on its value. The details are unclear without more context.

## Disclaimer

This script is provided as a sample and may require modifications to fit specific use cases or changes in the Ollama API. Please refer to the [API documentation](https://github.com/jmorganca/ollama/blob/main/docs/api.md) for any updates or changes.

## Credits

This script is inspired by the [GptHidra](https://github.com/evyatar9/GptHidra) repository. 

This script also uses a slightly modified version of one of [these Ghidra scripts](https://github.com/grayhatacademy/ghidra_scripts).

Many thanks to the contributors of these projects for their initial work.


