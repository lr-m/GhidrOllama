# Script for interacting with Ollama API running on local machine
# @author luke-r-m
# @category LLM-Assisted RE
# @keybinding q
# @menupath
# @toolbar

import urllib2
import json
import sys
import re
from ghidrollama_utils import leafblower
from ghidra.util.task import TaskMonitor
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.app.script import GhidraScript


# Print ASCII art Llama (essential)
def printLlama():
    print
    print("\
     .#.    .#.            \n\
     .##.   .##.        ~\n\
     .#+++++++#.    ~   ~  ~\n\
   .###.Ghidr .#.     ~    ~\n\
    .##.Ollama.#.    ~   ~\n\
     .#+++++++#.  .^ ^  ~  ~\n\
       #11001-#  ^-.^'.^ ~ ^\n\
      #11100-#   ^.'^.'^- ^.^\n\
     #01011-#  -^.^^-.^-^'.^\n\
    #10110--#  ^^..^.^-.^\n\
   #10101--#--^--^--^.'^\n\
   #-------#---^--^--^-#~\n\
   #-------------------#~~\n\
   .#-----------------#.\n\
    .#---------------#.\n\
     #--------------#.\n\
     #---#--##---#--#\n\
     #---#--##---#--#\n\
     #__# #_##__# #_#\n")



# General function to interact with the Ollama API
def interactWithOllamaAPI(model, prompt, c_code):
    monitor.setMessage("Model " + model + " is processing input...")
    print("\n>> Explanation:")
    url = 'http://localhost:11434/api/generate'
    data = {
        "model": model,
        "prompt": prompt + c_code
    }
    data = json.dumps(data)

    req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
    response = urllib2.urlopen(req)

    response_text = ""
    stats_summary = {}
    built_line = ""

    monitor.setMessage("Receiving response...")

    while True:
        character = response.read(1)
        built_line += character
	if character == '\n':
            response_data = json.loads(built_line)
            if "error" in response_data:
                raise ValueError(response_data["error"])
            if "response" in response_data:
                response_text += response_data["response"]
		printf('%s', response_data["response"]),
            if response_data["done"]:
                stats_summary = {
                    "total_duration": str(int(response_data["total_duration"]) / 1000000000) + 's'
                }
                break
            built_line = ""

    monitor.setMessage("Done!")

    return response_text, stats_summary


# Stolen from https://github.com/evyatar9/GptHidra/blob/main/GptHidra.py
def getCurrentDecompiledFunction():
    # Create a TaskMonitor object
    monitor = TaskMonitor.DUMMY

    # Create a DecompInterface object
    decompiler = DecompInterface()

    # Set the current program for the decompiler
    decompiler.openProgram(currentProgram)

    # Get the current address and the function containing it
    currentAddress = currentLocation.getAddress()
    function = getFunctionContaining(currentAddress)

    if function is None:
        raise ValueError("No function is currently selected.")

    # Decompile the function and get the resulting C code
    try:
        return decompiler.decompileFunction(function, 30, monitor).getDecompiledFunction().getC()
    except Exception as e:
        raise ValueError("Unable to decompile function: {}".format(e))


def getDecompiledFunctionAtAddress(address):
    # Create a TaskMonitor object
    monitor = TaskMonitor.DUMMY

    # Create a DecompInterface object
    decompiler = DecompInterface()

    # Set the current program for the decompiler
    decompiler.openProgram(currentProgram)

    # Get the current address and the function containing it
    function = getFunctionContaining(address)

    if function is None:
        raise ValueError("No function is currently selected.")

    # Decompile the function and get the resulting C code
    try:
        return decompiler.decompileFunction(function, 30, monitor).getDecompiledFunction().getC()
    except Exception as e:
        raise ValueError("Unable to decompile function: {}".format(e))
   

# Makes a request to the Ollama API to fetch a list of installed models, prompts user to select which model to use
def select_model():
    url = 'http://localhost:11434/api/tags'
    choice = None
    try:
        model_list_response = urllib2.urlopen(url)
        data = json.load(model_list_response)

        model_names = []
        for model in data['models']:
	    model_names.append(model['name'])

        choice = askChoice("GhidrOllama", "Please choose the model you want to use:", model_names, "Model Selection")
        print("Selected model: " + choice)

    except urllib2.HTTPError as e:
        print("HTTP Error {}: {}".format(e.code, e.reason))
    except urllib2.URLError as e:
        print("URL Error: {}".format(e.reason))
    except ValueError as e:
        print("Value Error: {}".format(e))

    return choice


# Returns the instruction that is currently selected in the listing window as a string
def getSelectedInstruction():
    listing = currentProgram.getListing()
    instruction = listing.getInstructionAt(currentLocation.getAddress())
    if instruction is not None:
    	return instruction.toString()
    return None


# Gets the selected assembly as a string
def getSelectedAssembly():
    instructions = ""
    listing = currentProgram.getListing()
    if currentSelection is not None:
        for address in currentSelection.getAddresses(True):
            instruction = listing.getInstructionAt(address)
            if instruction:
                instructions += '0x' + address.toString() + ': ' + instruction.toString() + '\n'
	return instructions
    else:
        print("No current selection.")
        return None


# Function to explain the selected function using the Ollama API
def explainFunction(model, c_code):
    prompt = "Can you briefly summarise what the following function does/what its purpose is? Try and explain in a few sentences.\n\n"
    return interactWithOllamaAPI(model, prompt, c_code)


# Function to suggest selected function name using the Ollama API
def suggestFunctionName(model, c_code):
    prompt = "If you had written the following C code, what would you name this function and parameters based on its functionality/behaviour? Completely disregard the function name and also the names of any functions called within. Make 100% sure you suggest a possible function name, and also names for the function parameters!\n\n"
    return interactWithOllamaAPI(model, prompt, c_code)


# Function to rewrite function with comments using the Ollama API
def addFunctionComments(model, c_code):
    prompt = "Could you rewrite the following function but the only thing that should change is that you add code comments? Keep them useful and consise, and only add them if they are important for understanding the code. The only output I want to see is the C function with added code comments.\n\n"
    return interactWithOllamaAPI(model, prompt, c_code)


# Function to rewrite the function with descriptive names and comments using the Ollama API
def tidyUpFunction(model, c_code):
    prompt = "The function name, local variables, and parameters are not named very well. Can you take a look at the function and replace the less-descriptive original names of function/arguments/local variables with more descriptive names that indicate its purpose? Please also add useful code comments, I want to see the full function rewritten using the more descriptive replacements. Other than the name changes and comments, the function must remain identical.\n\n"
    return interactWithOllamaAPI(model, prompt, c_code)


# Function to identify potential bugs using the Ollama API
def identifySecurityVulnerabilities(model, c_code):
    prompt = "Describe all vulnerabilities in this function with as much detail as possible, also produce a checklist of things to check that could potentially cause security vulnerabilities and memory corruptions.\n\n"
    return interactWithOllamaAPI(model, prompt, c_code)


# Function to suggest selected function name using the Ollama API
def suggestFunctionNameWithSuggestions(model, c_code, suggestions):
    prompt = "If you had written the following C code, what would you name this function and parameters based on its functionality/behaviour? Completely disregard the function name and also the names of any functions called within. There is a good chance that it is one of the following functions \"" + suggestions + " \". It is absolutely essential that you must 100% suggest a function name!\n\n"
    return interactWithOllamaAPI(model, prompt, c_code)


# Function to ask a question about the passed c code
def askQuestionAboutFunction(model, question, c_code):
    prompt = 'I have a question about the following function. \n' + question + '\nHere is the function:\n\n'
    return interactWithOllamaAPI(model, prompt, c_code)


# Function to explain the selected instruction using the Ollama API
def explainInstruction(model, instruction):
    architecture_name = currentProgram.getLanguage().getProcessor().toString()
    prompt = "Can you briefly explain the following instruction? The architecture is " + architecture_name + ". Can you also show the instruction format?\n\n"
    return interactWithOllamaAPI(model, prompt, instruction)


# Function to explain selected assembly using the Ollama API
def explainAssembly(model, assembly):
    architecture_name = currentProgram.getLanguage().getProcessor().toString()
    prompt = "Can you explain the following " + architecture_name + " assembly.\n\n"
    return interactWithOllamaAPI(model, prompt, assembly)


def main():
    printLlama()
    monitor.setMessage("Waiting for model select...")

    # Call the function to fetch and print the model list
    model = select_model()

    monitor.setMessage("Waiting for function select...")

    # Getting user input for the option
    options = [
	'1 - Explain the current function', 
	'2 - Suggest a suitable name for the current function', 
	'3 - Suggest function comments', 
	'4 - Rewrite function to be descriptive', 
	'5 - Ask question about current function', 
	'6 - Try and find bugs in the current function', 
	'7 - Locate + identify leafblower functions', 
	'8 - Explain selected instruction',  
	'9 - Explain selected assembly',
	'10 - Enter general prompt'
    ]

    try:
        # Prompt the user to select one of the available functions
        choice = askChoice("GhidrOllama", "What you want to ask the " + model + " model:", options, "Question Selection")
        option = int(choice.split(' ')[0])
        if option not in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
            print("Invalid option. Please select a valid option.")
        else:
            stats_summary = None
	    print("\nSelected Option {}".format(option))
            try:
                if option == 1:
                    c_code = getCurrentDecompiledFunction()
                    explanation, stats_summary = explainFunction(model, c_code)
                elif option == 2:
                    c_code = getCurrentDecompiledFunction()
                    explanation, stats_summary = suggestFunctionName(model, c_code)
		elif option == 3:
                    c_code = getCurrentDecompiledFunction()
                    explanation, stats_summary = addFunctionComments(model, c_code)
                elif option == 4:
                    c_code = getCurrentDecompiledFunction()
                    explanation, stats_summary = tidyUpFunction(model, c_code)
		elif option == 5:
                    c_code = getCurrentDecompiledFunction()
		    question = askString("GhidrOllama", "What do you want to ask about the function?")
                    explanation, stats_summary = askQuestionAboutFunction(model, question, c_code)
		elif option == 6:
                    c_code = getCurrentDecompiledFunction()
                    explanation, stats_summary = identifySecurityVulnerabilities(model, c_code)
		elif option == 7:
		    try:
                        # Create a ScriptTask and run the script
                        print 'Searching for potential POSIX leaf functions...'
                        leaf_finder = leafblower.LeafFunctionFinder(currentProgram)
                        leaf_finder.find_leaves()
                        leaf_finder.display()
			
			for leaf in leaf_finder.get_leaves():
			    print("\n\n> Analysing function at address: " + leaf.to_list()[0])
			    print('|'),
			    for elem in leaf.to_list():
				print(elem + ' |'),
			    print
			    c_code = getDecompiledFunctionAtAddress(toAddr(leaf.to_list()[0]))

                            explanation, stats_summary = suggestFunctionNameWithSuggestions(model, c_code, leaf.to_list()[4])
		    except Exception as e:
			print('Error: ' + e)
		elif option == 8:
                    c_code = getSelectedInstruction()
		    if c_code is not None:
                        explanation, stats_summary = explainInstruction(model, c_code)
		    else:
			print("No instruction selected!")
		elif option == 9:
		    c_code = getSelectedAssembly()
		    if c_code is not None:
                        explanation, stats_summary = explainAssembly(model, c_code)
		    else:
			print("No assembly selected!")
                elif option == 10:
                    prompt = askString("GhidrOllama", "Enter your prompt:")
                    explanation, stats_summary = interactWithOllamaAPI(model, prompt, '')
                
		# Print stats summary
                if stats_summary is not None:
                    print("\n\n>> Stats Summary:")
                    for key, value in stats_summary.items():
                        print(" {}: {}".format(key, value))            
            except ValueError as e:
                print(e)
    except ValueError:
        print("Invalid option.")
    except KeyboardInterrupt:
        print("\nTerminating the script.")
    print ''

main()
