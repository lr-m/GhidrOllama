<p align="center">

  <img src="https://github.com/luke-r-m/GhidrOllama/assets/47477832/c21b75ab-f186-4a2b-8206-15c1c1d5218b" width="200">

</p>

<p align="center">
  
  <img src="https://github.com/luke-r-m/GhidrOllama/assets/47477832/59e1b7e2-6331-4968-ac07-4b5ceded673b" width="400">

</p>

**Ollama API interaction Ghidra script for LLM-assisted reverse-engineering.**

## What is this?

This script interacts with the Ollama API hosted locally to interact with LLM's. It utilizes the Ollama API to perform various tasks such as explaining a C function's purpose, suggesting suitable names for functions, adding comments, explaining instructions, and answering questions without leaving Ghidra. This script is inspired by [GptHidra](https://github.com/evyatar9/GptHidra).

## Prerequisites

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Ollama](https://github.com/jmorganca/ollama)
- [Any of the Ollama models](https://ollama.ai/library)

### Ollama Setup

Feel free to replace `codellama:7b` with any model from the collection of [Ollama Models](https://ollama.ai/library)

```
curl https://ollama.ai/install.sh | sh
ollama run codellama:7b
```

Now you should have a docker container running that is hosting the API

## Usage

1. Place the script in the Ghidra script directory or create a new script in the Script Manager window and copy the contents of *GhidrOllama.py*.
2. Find a function you want to feed to the LLM
3. Run the script from the Script Manager
4. Select the model you want to use
5. Select how you want to function to be analysed
6. Wait until the output is printed to the console (wait time varies depending on model and specifications of host)

## Functionality

- Can explain the function that is currently in the decompiler window
- Can suggest a name for the function and its arguments
- Can rewrite the function with recommended comments
- Can completely rewrite the function, trying to improve function/parameter/variable names and also add comments
- Can explain the currently selected instruction in the listing window
- Also allows entry of any text prompt

## Notes

- It is worth noting that the analysis will only be as good as the model, this script basically just bridges the models and Ghidra.
- The better the model (more parameters, slower) the more comprehensive and correct the analysis will be.
- If you want a quick overview of a function, *codellama:7b* is pretty quick and gives a decent analysis/can identify simple functions such as *strcpy()* (most of the time!)

## Function Example

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

The following analysis was performed using the *codellama:7b* model.

### Option 1 - Function Summary

> This function takes two parameters, a character pointer `param_1` and a character `param_2`. The purpose of this function is to scan the string pointed to by `param_1` for the first occurrence of the character `param_2`, and if it is found, return a pointer to that position in the string. If the character `param_2` is not found in the string, then the function returns a null pointer (i.e., `(char *)0x0`).
The function uses a loop to scan the characters of the string pointed to by `param_1`. It checks each character against the `param_2` character, and if they match, it sets the `pcVar2` variable to point to the current position in the string. If no match is found, then the function returns a null pointer.
The purpose of this function is not immediately clear from its name or parameters. It seems to be used for searching a string for a specific character, but it's possible that there are other uses for this function as well.

### Option 2 - Function Naming

> The function FUN_801a7490 takes two parameters, `char *param_1` and `char param_2`.
Based on the functionality of this function, I would suggest the following names for the parameters:
> * `char *param_1`: This parameter represents a string, and it is used as an input to the function. I would suggest naming it `input_string`.
> * `char param_2`: This parameter represents a single character, and it is used as an input to the function. I would suggest naming it `search_character`.
As for the name of the function itself, I would suggest `strchr` (short for "string character"). This name reflects the functionality of the function, which is to search for a specific character in a string and return its position.

### Option 3 - Add Comments

> Here is the rewritten function with code comments:
> ```c
> char * FUN_801a7490(char *param_1, char param_2) {
>   // Initialize variables
>   char cVar1 = *param_1;
>   char *pcVar2 = (char *)0x0;
>   
>   // Check if the first character is a null terminator
>   if (cVar1 == '\0') {
>     // If it is, set the output pointer to null
>     pcVar2 = (char *)0x0;
>   }
>   else {
>     // If it is not, iterate through the string until a null terminator is found
>     do {
>       // Check if the current character matches the target character
>       if (param_2 == cVar1) {
>         // If it does, set the output pointer to the current position in the string
>         pcVar2 = param_1;
>       }
>       // Increment the input pointer and get the next character
>       param_1 = param_1 + 1;
>       cVar1 = *param_1;
>     } while (cVar1 != '\0');
>   }
>   if (param_2 != '\0') {
>     // If the target character is not a null terminator, set the output pointer to null
>     param_1 = pcVar2;
>   }
>   
>   return param_1;
> }
> ```
> The function takes two parameters: `param_1`, which is a pointer to a string, and `param_2`, which is a character. The function searches the string pointed to by `param_1` for the target character specified in `param_2`. If the target character is found, the function sets the output pointer to point to the first occurrence of the target character in the input string. If the target character is not found or if it is a null terminator, the function sets the output pointer to null.

### Option 4 - Rewrite Function

> Sure, I can help you with that. Here is the function rewritten using more descriptive names:
> 
> ```c
> char *find_substring(char *input_string, char target_character) {
>     // Initialize variables
>     char current_character = '\0';
>     char *substring_start = NULL;
> 
>     // Check if input string is not empty and target character is not null
>     if (input_string != NULL && target_character != '\0') {
>         // Iterate through the input string and find the first occurrence of the target character
>         while (*input_string != '\0') {
>             current_character = *input_string;
>             if (current_character == target_character) {
>                 substring_start = input_string;
>                 break;
>             }
> 
>             // Increment the input string pointer
>             input_string++;
>         }
>     }
> 
>     // Return the substring start pointer or null if not found
>     return substring_start;
> }
> ```
> 
> This function takes two parameters: an input string and a target character. The function iterates through the input string and finds the first occurrence of the target character, returning a pointer to the beginning of the substring. If the target character is not found in the input string, the function returns NULL.

## Instruction Example

The script can also provide descriptions of instructions in the listing window (saves browsing programmers manuals), here is an example for that:

```
bne $v0,$zero,LAB_801a74a4
```

### Describe Instruction

> Sure! Here's an explanation of the `bne` instruction in MIPS and its instruction format:
The `bne` instruction is a branch instruction that branches to a specified target address if two specified values are not equal. The syntax for this instruction is as follows:
> ```
> bne <rs>,<rt>,<immediate>
> ```
> Here, `<rs>` is the first operand (a general-purpose register), `<rt>` is the second operand (also a general-purpose register), and `<immediate>` is an immediate value that specifies the target address.
For example, in the instruction `bne v0,zero,0x801a74a4`, the `v0` register is compared to the `zero` register, and if they are not equal, control flow branches to the specified target address of `0x801a74a4`.

## Disclaimer

This script is provided as a sample and may require modifications to fit specific use cases or changes in the Ollama API. Please refer to the [API documentation](https://github.com/jmorganca/ollama/blob/main/docs/api.md) for any updates or changes.

## Credits

This script is inspired by the [GptHidra](https://github.com/evyatar9/GptHidra) repository. Special thanks to the contributors of the GptHidra project for their initial work.

