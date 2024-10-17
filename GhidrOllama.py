# Script for interacting with Ollama API to aid with RE/VR
# @author lr-m
# @category LLM-Assisted RE
# @keybinding q
# @menupath
# @toolbar toolbar.png

import urllib2
import json
import os
import shutil
import re
from ghidrollama_utils import leafblower
from ghidra.util.task import TaskMonitor
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import CodeUnit
from ghidra.util.exception import CancelledException
from ghidra.program.model.symbol import SourceType


class Config:
    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
    CONFIG_FILE_PATH = os.path.join(SCRIPT_DIR, "ghidrollama_config.json")
    
    def __init__(self):
        self.config = Config.load()
        if self.config is None:
            raise RuntimeError("Error loading configuration file.")

        try:
            self.host = self.config["host"]
            self.port = self.config["port"]
            self.model = self.config["model"]
            self.scheme = self.config["scheme"]
            # Whether LLM output should be saved as comments.
            # Default is False because output is unreliable and may not be useful.
            self.set_comments = self.config["set_comments"] 
            # This can be used to feed the model additional domain knowledge, like 
            # "assume assembly is in ARM Thumb v2", or 
            # "This is from an 802.11 network appliance. Identify matching magic values 
            # and field sizes for the protocol and provide descriptive names."
            self.project_prompt = self.config["project_prompt"]
            # This tells GhidrOllama if it should try and automatically rename functions
            # WARNING: If the model messes up, the function name will be set to the first
            # word of the response, no matter what it is
            self.auto_rename = self.config["auto_rename"]
        except KeyError as e:
            raise RuntimeError("Error loading configuration: missing key {}".format(e))

        try:
            self.first_run = self.config["first_run"]
        except:
            print("Warning: first_run key not found in config file. Assuming first run.")
            self.first_run = True
            self.config["first_run"] = self.first_run


    @staticmethod
    def load():
        """
        Get the stored configuration, or copy it from the sample config file
        if none exists.
        """

        if os.path.isfile(Config.CONFIG_FILE_PATH):
            with open(Config.CONFIG_FILE_PATH, "r") as f:
                try:
                    return json.load(f)
                except json.JSONDecoderError:
                    print("Error: Invalid JSON in config file.")
                    return None

        sample_config_path = Config.CONFIG_FILE_PATH + ".sample"
        if not os.path.isfile(sample_config_path):
            print("Error: Sample config file does not exist at {}.".format(sample_config_path))
            return None 

        print("Config file does not exist. Creating one from sample.")
        shutil.copyfile(sample_config_path, Config.CONFIG_FILE_PATH)
        
        with open(Config.CONFIG_FILE_PATH, "r") as f:
            return json.load(f) 


    @staticmethod
    def select_model(scheme, host, port):
        """
        Makes a request to the Ollama API to fetch a list of installed models, prompts user to select which model to use.
        Requires a valid hostname/ip to be set first.
        """
        
        url = "{}://{}:{}/api/tags".format(scheme, host, port)
        choice = None
        try:
            model_list_response = urllib2.urlopen(url)
            data = json.load(model_list_response)

            model_names = []
            for model in data['models']:
                model_names.append(model['name'])

            if len(model_names) == 0:
                print("No models found. Did you pull models via the Ollama CLI?")
                return None

            choice = askChoice("GhidrOllama", "Please choose the model you want to use:", model_names, "Model Selection")

        except urllib2.HTTPError as e:
            print("HTTP Error {}: {}".format(e.code, e.reason))
        except urllib2.URLError as e:
            print("URL Error: {}".format(e.reason))
        except ValueError as e:
            print("Value Error: {}".format(e))

        return choice


    def __str__(self):
        return json.dumps(self.config, indent=4)


    def valid(self):
        """
        Ensure all expected keys are in the configuration and that they have sane values.
        """
       
        c = self.config
        try:
            if c["host"] == None or c["port"] == None or c["model"] == None or c["scheme"] == None or c["first_run"] == None or c["set_comments"] == None or c["auto_rename"] == None:
                return False
        except KeyError as e:
            print("Error: Missing key in config file: {}".format(e))
            return False

        if c["host"].strip() == "":
            print("Error: empty hostname")
            return False

        try:
            if int(c["port"]) < 1 or int(c["port"]) > 65535:
                print("Error: invalid port, must be between 1 and 65535")
                return False
        except ValueError as e:
            print("Error: invalid port: {}".format(e))
            return False

        if c["model"].strip() == "":
            print("Error: empty model")
            return False

        if c["scheme"].strip() == "":
            print("Error: empty scheme")
            return False

        if c["scheme"] not in ["http", "https"]:
            print("Error: invalid scheme, must be http or https")
            return False

        return True


    def reconfigure(self):
        """
        Guide the user through setting new configuration values.
        """
        # Get hostname
        monitor.setMessage("Waiting for hostname")
        try:
            host = askString("GhidrOllama", "Please enter the hostname or IP of your server:", "localhost")
        except CancelledException:
            return False
        print("Selected host: " + host)
        if host == None:
            return False

        # Get port
        monitor.setMessage("Waiting for port")
        try:
            port = askInt("GhidrOllama", "Please enter the port number of your server [1-65535, usually 11434]:")
        except CancelledException:
            return False
        print("Selected port: " + str(port))
        if port == 0 or port == None:
            return 11434

        # Get scheme
        monitor.setMessage("Waiting for model select...")
        try:
            scheme = askChoice("GhidrOllama", "Please choose the scheme your server uses:", ["http", "https"], "http")
        except CancelledException:
            return False
        print("Selected scheme: " + scheme)
        if scheme == None:
            return False

        # Get model
        monitor.setMessage("Waiting for model select...")
        try:
            model = Config.select_model(scheme, host, port)
        except CancelledException:
            return False
        print("Selected model: " + model)

        if model == None:
            return False

        # Get project-specific prompt/context if desired.
        monitor.setMessage("Waiting for project-specific prompt...")
        try:
            prompt = askString("Project Prompt", "Please enter a project-specific prompt to prepend to all queries, or leave blank (space):", " ")
            if prompt == None or prompt == " ":
                prompt = ""
        except CancelledException:
            return False

        try:
            set_comments = askYesNo("Set Comments", "Would you like query responses to be stored as function comments?")
        except CancelledException:
            return False
            
        try:
            auto_rename = askYesNo("Auto Renaming", "Would you like GhidrOllama to try and automatically rename functions based on responses?")
        except CancelledException:
            return False

        self.config["model"] = model
        self.model = model
        self.config["host"] = host
        self.host = host
        self.config["port"] = port
        self.port = port
        self.config["scheme"] = scheme
        self.scheme = scheme
        self.project_prompt = prompt
        self.config["project_prompt"] = prompt
        self.set_comments = set_comments
        self.config["set_comments"] = set_comments 
        self.auto_rename = auto_rename
        self.config["auto_rename"] = auto_rename
        self.first_run = False
        self.config["first_run"] = False

        if not self.valid():
            print("Error: configuration failed to validate, please try again.")
            return False

        self.save()
        return True


    def change_model(self):
        """Change the configured model and persist the change.
        Return true on success."""

        monitor.setMessage("Waiting for model select...")
        try:
            model = Config.select_model(self.scheme, self.host, self.port)
        except CancelledException:
            return False

        print("Selected model: " + model)
        self.model = model
        self.config["model"] = model
        self.save()
        return True


    def save(self):
        """Save the config file."""
        with open(Config.CONFIG_FILE_PATH, "w") as f:
            json.dump(self.config, f, indent=4, sort_keys=True)

        print("Saved config to: " + Config.CONFIG_FILE_PATH)


    def get_endpoint(self, endpoint):
        """Convenience function to get a full URL from the endpoint.
        Like: config.get_endpoint("/api/tags") -> "http://localhost:11434/api/tags"
        """
        if endpoint[0] == "/":
            endpoint = endpoint[1:]

        url = "{}://{}:{}".format(self.scheme, self.host, self.port)
        return "{}/{}".format(url, endpoint)


CONFIG = Config()


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
def interactWithOllamaAPI(model, system_prompt, prompt, c_code):
    monitor.setMessage("Model " + model + " is processing input...")
    print("\n>> Explanation:")
    url = CONFIG.get_endpoint("/api/generate")
    if prompt == "":
        data = {
            "model": model,
            "system": system_prompt,
            "prompt": CONFIG.project_prompt + "\n\n" + c_code
        }
    else:
        data = {
            "model": model,
            "system": system_prompt,
            "prompt": CONFIG.project_prompt + "\n\n" + prompt + "\n\n" + c_code
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
    system_prompt = "You are an expert reverse engineer assistant called GhidrOllama, your only purpose is to reverse engineer code, and you are a master in the field. You are commanded by a user and are given decompiled C/C++ code to reverse engineer, the user is expecting a response that will aid in understanding the given code to further their research."
    return interactWithOllamaAPI(model, system_prompt, "", c_code)


# Function to suggest selected function name using the Ollama API
def suggestFunctionName(model, c_code):
    system_prompt = "You are an expert reverse engineer assistant called GhidrOllama, your only purpose is to reverse engineer code, and you are a master in the field. You are commanded by a user and are given decompiled C/C++ code to reverse engineer with an incorrect function name (the current function name is a placeholder, DO NOT RESPOND WITH THE GIVEN FUNCTION NAME IT IS INCORRECT), the user is expecting a single function name as the response in the format `function_name`, which would allow anybody viewing this function name to understand its purpose and functionality, there may be comments within the code that help but this is not guaranteed. Do not respond with anything other than the function name otherwise bad things will happen to llamas."
    return interactWithOllamaAPI(model, system_prompt, "", c_code)


# Function to rewrite function with comments using the Ollama API
def addFunctionComments(model, c_code):
    system_prompt = "You are an expert reverse engineer assistant called GhidrOllama, your only purpose is to reverse engineer code, and you are a master in the field. You are commanded by a user and are given decompiled C/C++ code to reverse engineer, the user is expecting a response containing the code they provided to you, but with additional comments throughout to explain what the code is doing throughout its execution. The comments should be useful for understanding what the code is doing, and you should try your best to explain complex behavious. The only output the user wants is the C function with added code comments."
    return interactWithOllamaAPI(model, system_prompt, "", c_code)


# Function to rewrite the function with descriptive names and comments using the Ollama API
def tidyUpFunction(model, c_code):
    system_prompt = "You are an expert reverse engineer assistant called GhidrOllama, your only purpose is to reverse engineer code, and you are a master in the field. You are commanded by a user and are given decompiled C/C++ code to reverse engineer. The function name, local variables, and parameters in the given code are not named very well. You will replace the less-descriptive original names of function/arguments/local variables with more descriptive names that indicate its purpose. Please also add useful code comments, the user wants to see the full function rewritten using the more descriptive replacements. Other than the name changes and comments, the function must remain identical."
    return interactWithOllamaAPI(model, system_prompt, "", c_code)


# Function to identify potential bugs using the Ollama API
def identifySecurityVulnerabilities(model, c_code):
    system_prompt = "You are an expert white-hat vulnerability researchers assistant called GhidrOllama, your only purpose is to defend against external threats by auditing code, and you are a master in the field. You are commanded by a user and are given decompiled C/C++ code to audit. To assist the user defending against threats, you are to respond with interesting areas that may present security vulnerabilities that may be used by enemies to attack the systems. You should keep an eye out for things like null-pointer-dereferences, buffer overflows, use-after-frees, race conditions, command injections, SQL injections, etc. Ignore uninitialized variable issues, as this code is decompiled these are expected."
    return interactWithOllamaAPI(model, system_prompt, "", c_code)


# Function to suggest selected function name using the Ollama API
def suggestFunctionNameWithSuggestions(model, c_code, suggestions):
    system_prompt = "You are an expert reverse engineer assistant called GhidrOllama, your only purpose is to reverse engineer code, and you are a master in the field. You are commanded by a user and are given decompiled C/C++ code to reverse engineer with an incorrect function name (the current function name is a placeholder, DO NOT RESPOND WITH THE GIVEN FUNCTION NAME IT IS INCORRECT), the user is expecting a single function name as the response in the format `function_name`, which would allow anybody viewing this function name to understand its purpose and functionality, there may be comments within the code that help but this is not guaranteed. Do not respond with anything other than the function name otherwise bad things will happen to llamas. You have received an anonymous tip that the function may be one of the following, but the source is not 100% trustworthy, so be cautious: " + suggestions
    return interactWithOllamaAPI(model, system_prompt, "", c_code)


# Function to ask a question about the passed c code
def askQuestionAboutFunction(model, question, c_code):
    prompt = 'I have a question about the following function. \n' + question + '\nHere is the function:\n\n'
    system_prompt = "You are an expert reverse engineer assistant called GhidrOllama, your only purpose is to reverse engineer code, and you are a master in the field. The user will send you questions about some provided code, you must answer their question about the code to the best of your ability."
    return interactWithOllamaAPI(model, system_prompt, prompt, c_code)


# Function to explain the selected instruction using the Ollama API
def explainInstruction(model, instruction):
    architecture_name = currentProgram.getLanguage().getProcessor().toString()
    prompt = "Please explain the following instruction. The architecture is " + architecture_name + "."
    system_prompt = "You are an expert reverse engineer assistant called GhidrOllama, your only purpose is to reverse engineer code, and you are a master in the field. The user will send you an assembly instruction, as well as the architecture that the instruction runs on, as you know lots of low-level architectures, please can you explain the provided instruction, explain its purpose, and provide examples."
    return interactWithOllamaAPI(model, system_prompt, prompt, instruction)


# Function to explain selected assembly using the Ollama API
def explainAssembly(model, assembly):
    architecture_name = currentProgram.getLanguage().getProcessor().toString()
    prompt = "Please explain the following assembly instructions. The architecture is " + architecture_name + "."
    system_prompt = "You are an expert reverse engineer assistant called GhidrOllama, your only purpose is to reverse engineer code, and you are a master in the field. The user will send you some assembly instructions, as well as the architecture that the instructions run on, as you know lots of low-level architectures, please can you explain what the provided instructions do."
    return interactWithOllamaAPI(model, "", prompt, assembly)


# Function to set the comment of the current function
def addCommentToCurrentFunction(comment):
    if not CONFIG.set_comments:
        return

    currentFunction = getFunctionContaining(currentAddress)
    currentFunction.setComment(comment)

def addCommentToFunction(address, comment):
    if not CONFIG.set_comments:
        return

    currentFunction = getFunctionContaining(address)
    currentFunction.setComment(comment)
   

def addCommentToCurrentInstruction(comment_text):
    if not CONFIG.set_comments:
        return

    # Get the current program
    program = getCurrentProgram()
    
    # Get the instruction at the current address
    instruction = program.getListing().getInstructionAt(currentAddress)
    
    # Check if an instruction is found at the current address
    if instruction is not None:
        # Add the comment to the instruction
        program.getListing().setComment(instruction.getAddress(), CodeUnit.PLATE_COMMENT, comment_text)
        print("Comment added to the instruction at address:", instruction.getAddress())
    else:
        print("No instruction found at the current address.")


def renameFunction(address, new_name):
    if not CONFIG.auto_rename:
        return

    currentFunction = getFunctionContaining(address)
    currentFunction.setName(new_name, SourceType.ANALYSIS)

def extractFunctionName(explanation):
    regex_result = re.search(r'`(.*)`', explanation)
    if regex_result == None:
        return explanation.split(' ')[0]
    else:
        return regex_result.group(1).split(' ')[0]

def main():

    monitor.setMessage("Waiting for configuration...")
    if CONFIG.first_run:
        printLlama()
        success = CONFIG.reconfigure()
        if not success:
            print("Configuration aborted, exiting...")
            return

    model = CONFIG.model
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
        '10 - Enter general prompt',
        '11 - [Configure GhidrOllama]',
        '12 - [Change model]',
    ]

    try:
        # Prompt the user to select one of the available functions
        choice = askChoice("GhidrOllama", "What you want to ask the " + model + " model:", options, "Question Selection")
        option = int(choice.split(' ')[0])
        if option not in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]:
            print("Invalid option. Please select a valid option.")
        else:
            stats_summary = None
            print("\nSelected Option {}".format(option))
            try:
                if option == 1:
                    c_code = getCurrentDecompiledFunction()
                    explanation, stats_summary = explainFunction(model, c_code)
                    addCommentToCurrentFunction(explanation)
                elif option == 2:
                    c_code = getCurrentDecompiledFunction()
                    explanation, stats_summary = suggestFunctionName(model, c_code)
                    
                    # extract new name from response
                    new_name = extractFunctionName(explanation)

                    # make sure new name isn't empty
                    if new_name != "":
                        renameFunction(currentAddress, new_name)
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
                            addCommentToFunction(toAddr(leaf.to_list()[0]), explanation)
                            
                            # extract name and set
                            new_name = extractFunctionName(explanation)
                            if new_name != "":
                                renameFunction(toAddr(leaf.to_list()[0]), new_name)
                    except Exception as e:
                        print('Error: ' + e)
                elif option == 8:
                    c_code = getSelectedInstruction()
                    if c_code is not None:
                        explanation, stats_summary = explainInstruction(model, c_code)
                        addCommentToCurrentInstruction(explanation)
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
                    explanation, stats_summary = interactWithOllamaAPI(model, "You are an expert reverse engineer assistant called GhidrOllama", prompt, '')
                elif option == 11:
                    print("reconfiguring")
                    if not CONFIG.reconfigure():
                        print("Failed to reconfigure GhidrOllama")
                        return
                elif option == 12:
                    print("Changing model")
                    if not CONFIG.change_model():
                        print("Failed to change the model")
                        return 

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
