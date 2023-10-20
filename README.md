# Ollama API Interaction Script for Ghidra

This script interacts with the Ollama API, which is running on the local machine. It utilizes the Ollama API to perform various tasks such as explaining a C function's purpose and suggesting suitable names for functions. This script is based on the [GptHidra](https://github.com/evyatar9/GptHidra) repository.

## Prerequisites

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Ollama](https://github.com/jmorganca/ollama)
- [Any of the Ollama models](https://ollama.ai/library)

## Usage

1. Place the script in the Ghidra script directory or create a new script in the Script Manager window and copy the contents of *GhidrOllama.py*.
2. Find a function you want to feed to the LLM
3. Run the script from the Script Manager
4. Select the model you want to use
5. Select how you want to function to be analysed
6. Wait until the output is printed to the console (wait time varies depending on model and specifications of host)

## Notes

- It is worth noting that the analysis will only be as good as the model, this script basically just bridges the models and Ghidra.
- The better the model (more parameters, slower) the more comprehensive and correct the analysis will be.
- If you want a quick overview of a function, *codellama:7b* is pretty quick and gives a decent analysis/can identify simple functions such as strcpy

## Example

Below is an implementation of *strcpy()* as seen in Ghidra decompile window with stripped symbols:

```c
uint * FUN_801a7070(uint *param_1,uint *param_2)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  int iVar6;
  
  uVar2 = DAT_801f0710;
  iVar6 = DAT_801f0708;
  puVar4 = param_1;
  if ((((uint)param_2 | (uint)param_1) & 3) != 0) {
    do {
      cVar1 = *(char *)param_2;
      param_2 = (uint *)((int)param_2 + 1);
      *(char *)puVar4 = cVar1;
      puVar4 = (uint *)((int)puVar4 + 1);
    } while (cVar1 != '\0');
    return param_1;
  }
  uVar5 = *param_2;
  uVar3 = ~uVar5 & uVar5 - DAT_801f0708 & DAT_801f0710;
  while (uVar3 == 0) {
    *puVar4 = uVar5;
    param_2 = param_2 + 1;
    uVar5 = *param_2;
    puVar4 = puVar4 + 1;
    uVar3 = uVar2 & ~uVar5 & uVar5 - iVar6;
  }
  iVar6 = 0;
  do {
    cVar1 = *(char *)((int)param_2 + iVar6);
    *(char *)((int)puVar4 + iVar6) = cVar1;
    iVar6 = iVar6 + 1;
  } while (cVar1 != '\0');
  return param_1;
}
```

The following analysis was performed using the *codellama:7b* model.

### Option 1 - Function Summary

> This is a function named "FUN_801a7070" that takes two arguments of type "uint*" and returns the same value. The function appears to be responsible for copying data from one buffer to another, but it does so in a way that is not entirely clear.The function starts by declaring several local variables, including a variable named "uVar2" that appears to be initialized to some constant value. It then uses the "DAT_801f0708" and "DAT_801f0710" symbols to initialize two other local variables, "iVar6" and "uVar3", respectively.The function then enters a loop that iterates over the bytes of one buffer and copies them to another buffer. The loop appears to be checking for certain conditions before copying each byte from one buffer to another. It is not entirely clear what these conditions are or how they should be evaluated.Overall, this function appears to be responsible for copying data from one buffer to another in a way that involves some sort of processing or manipulation of the data. However, it is not entirely clear how this processing or manipulation should be done, and more information would be needed to fully understand its purpose.

### Option 2 - Function Naming

> Based on the functionality of this code, I would suggest the following names for the function and its parameters:* Function name: `stringCopy` or `copyString`* Parameters:	+ `source`: The source string to be copied.	+ `destination`: The destination buffer where the copy will be stored.The function's functionality can be summarized as follows:1. It takes two parameters, `source` and `destination`, which are pointers to strings.2. It copies the characters from the source string to the destination buffer, character by character.3. It uses a loop to iterate over each character in the source string, and it copies each character to the corresponding position in the destination buffer.4. It returns the `destination` parameter, which now contains a copy of the original source string.

## Disclaimer

This script is provided as a sample and may require modifications to fit specific use cases or changes in the Ollama API. Please refer to the [API documentation](https://github.com/jmorganca/ollama/blob/main/docs/api.md) for any updates or changes.

## Credits

This script is inspired by the [GptHidra](https://github.com/evyatar9/GptHidra) repository. Special thanks to the contributors of the GptHidra project for their initial work.

