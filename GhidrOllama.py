# Script for interacting with Ollama API running on local machine
# Used https://github.com/evyatar9/GptHidra as a starting point

import urllib2
import json
from ghidra.util.task import TaskMonitor
from ghidra.app.decompiler import DecompInterface

# General function to interact with the Ollama API
def interactWithOllamaAPI(model, prompt, c_code):
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

    try:
        while True:
            line = response.readline()
            if not line:
                break
            response_data = json.loads(line)
            if "error" in response_data:
                raise ValueError(response_data["error"])
            if "response" in response_data:
                response_text += response_data["response"]

            if response_data["done"]:
                stats_summary = {
                    "total_duration": response_data["total_duration"],
                    "load_duration": response_data["load_duration"],
                    "prompt_eval_count": response_data["prompt_eval_count"],
                    "eval_count": response_data["eval_count"],
                    "eval_duration": response_data["eval_duration"]
                }
                break
    except KeyError as e:
        raise ValueError("KeyError: {}".format(e))

    response_text = response_text.replace("\n", "")

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

        choice = askChoice("Choice", "Please choose the model you want to use", model_names, "Model Selection")
        print("Selected model: " + choice)

    except urllib2.HTTPError as e:
        print("HTTP Error {}: {}".format(e.code, e.reason))
    except urllib2.URLError as e:
        print("URL Error: {}".format(e.reason))
    except ValueError as e:
        print("Value Error: {}".format(e))

    return choice

# Function to explain the code using the OpenAI API
def explainFunction(model, c_code):
    prompt = "Can you briefly summarise what the following function does/what its purpose is?\n\n"
    return interactWithOllamaAPI(model, prompt, c_code)


# Function to suggest a function name using the OpenAI API
def suggestFunctionName(model, c_code):
    prompt = "If you had written the following C code, what would you name this function and parameters based on its functionality/behaviour? Completely disregard the function name and also the names of any functions called within:\n\n"
    return interactWithOllamaAPI(model, prompt, c_code)


def main():
    # Call the function to fetch and print the model list
    model = select_model()

    # Getting user input for the option
    options = ['1 - Explain the selected function', '2 - Suggest a suitable name for the function', '3 - Enter prompt']
    try:
        # Prompt the user to select one of the installed models
        choice = askChoice("Choice", "Pick what you want to ask the model", options, "Question Selection")
        option = int(choice.split(' ')[0])
        if option not in [1, 2, 3]:
            print("Invalid option. Please select a valid option.")
        else:
	    print("\nSelected Option {}".format(option))
            try:
                if option == 1:
                    c_code = getCurrentDecompiledFunction()
                    explanation, stats_summary = explainFunction(model, c_code)
                    print("\nExplanation:")
                    print(explanation.replace('<|endoftext|>', ''))
                    print("\nStats Summary:")
                    for key, value in stats_summary.items():
                        print(" {}: {}".format(key, value))
                elif option == 2:
                    c_code = getCurrentDecompiledFunction()
                    explanation, stats_summary = suggestFunctionName(model, c_code)
                    print("\nExplanation:")
                    print(explanation.replace('<|endoftext|>', ''))
                    print("\nStats Summary:")
                    for key, value in stats_summary.items():
                        print(" {}: {}".format(key, value))
                elif option == 3:
                    prompt = askString("GhidrOllama", "Enter your prompt:")
                    explanation, stats_summary = interactWithOllamaAPI(model, prompt, '')
                    print("\nExplanation:")
                    print(explanation.replace('<|endoftext|>', ''))
                    print("\nStats Summary:")
                    for key, value in stats_summary.items():
                        print(" {}: {}".format(key, value))            
            except ValueError as e:
                print(e)
    except ValueError:
        print("Invalid option. Please enter a number.")
    except KeyboardInterrupt:
        print("\nTerminating the script.")

main()
