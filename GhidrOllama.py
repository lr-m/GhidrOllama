# Script for interacting with Ollama API to aid with RE/VR
# @author lr-m
# @category LLM-Assisted RE
# @keybinding q
# @toolbar toolbar.png

import urllib2
import re
import sys
from ghidrollama_utils.config import Config
from ghidrollama_utils.helper import *
from ghidrollama_utils.ghidrollama_subscripts import leafblower
import json

this = sys.modules[__name__]

# General function to interact with the Ollama API
def interact_with_ollama(model, system_prompt, prompt, c_code):
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


# Function to suggest selected function name using the Ollama API
def suggest_function_names_with_suggsted(model, c_code, suggestions):
    system_prompt = (
        "You are an expert reverse engineer assistant called "
        "GhidrOllama, your only purpose is to reverse engineer "
        "code, and you are a master in the field. You are commanded "
        "by a user and are given decompiled C/C++ code to reverse "
        "engineer with an incorrect function name (the current "
        "function name is a placeholder, DO NOT RESPOND WITH THE "
        "GIVEN FUNCTION NAME IT IS INCORRECT), the user is "
        "expecting a single function name as the response in the "
        "format `function_name`, which would allow anybody viewing "
        "this function name to understand its purpose and functionality, "
        "there may be comments within the code that help but this is not "
        "guaranteed. Do not respond with anything other than the function "
        "name otherwise bad things will happen to llamas. You have received "
        "an anonymous tip that the function may be one of the following, but "
        "the source is not 100% trustworthy, so be cautious: " + suggestions
    )
    return interact_with_ollama(model, system_prompt, "", c_code)


def handle_explain_function(model):
    c_code = helper.get_current_decompiled_function()
    
    system_prompt = (
        "You are an expert reverse engineer assistant "
        "called GhidrOllama, your only purpose is to reverse "
        "engineer code, and you are a master in the field. "
        "You are commanded by a user and are given decompiled "
        "C/C++ code to reverse engineer, the user is expecting "
        "a response that will aid in understanding the given "
        "code to further their research."
    )
    
    explanation, stats_summary = interact_with_ollama(
        model,
        system_prompt,
        "",
        c_code
    )
    
    if CONFIG.set_comments:
        helper.add_comment_to_current_function(explanation)
    
    return stats_summary

def handle_suggest_function_name(model):
    c_code = helper.get_current_decompiled_function()

    system_prompt = (
        "You are an expert reverse engineer assistant called "
        "GhidrOllama, your only purpose is to reverse engineer "
        "code, and you are a master in the field. You are "
        "commanded by a user and are given decompiled C/C++ "
        "code to reverse engineer with an incorrect function "
        "name (the current function name is a placeholder, DO "
        "NOT RESPOND WITH THE GIVEN FUNCTION NAME IT IS "
        "INCORRECT), the user is expecting a single function "
        "name as the response in the format `function_name`, "
        "which would allow anybody viewing this function name "
        "to understand its purpose and functionality, there may "
        "be comments within the code that help but this is not "
        "guaranteed. Do not respond with anything other than the "
        "function name otherwise bad things will happen to llamas."
    )
    explanation, stats_summary = interact_with_ollama(model, system_prompt, "", c_code)

    new_name = helper.extract_function_name(explanation)
    if (new_name != "") and CONFIG.auto_rename:
        helper.rename_function(currentAddress, new_name)
    return stats_summary

def handle_add_function_comments(model):
    c_code = helper.get_current_decompiled_function()

    system_prompt = (
        "You are an expert reverse engineer assistant called "
        "GhidrOllama, your only purpose is to reverse engineer "
        "code, and you are a master in the field. You are "
        "commanded by a user and are given decompiled C/C++ code "
        "to reverse engineer, the user is expecting a response "
        "containing the code they provided to you, but with "
        "additional comments throughout to explain what the code "
        "is doing throughout its execution. The comments should "
        "be useful for understanding what the code is doing, and "
        "you should try your best to explain complex behaviours. "
        "The only output the user wants is the C function with "
        "added code comments."
    )
    explanation, stats_summary = interact_with_ollama(model, system_prompt, "", c_code)

    if CONFIG.set_comments:
        helper.add_comment_to_current_function(explanation)

    return stats_summary

def handle_tidy_up_function(model):
    c_code = helper.get_current_decompiled_function()

    system_prompt = (
        "You are an expert reverse engineer assistant called "
        "GhidrOllama, your only purpose is to reverse engineer "
        "code, and you are a master in the field. You are "
        "commanded by a user and are given decompiled C/C++ code "
        "to reverse engineer. The function name, local variables, "
        "and parameters in the given code are not named very well. "
        "You will replace the less-descriptive original names of "
        "function/arguments/local variables with more descriptive "
        "names that indicate its purpose. Please also add useful "
        "code comments, the user wants to see the full function "
        "rewritten using the more descriptive replacements. Other "
        "than the name changes and comments, the function must "
        "remain identical."
    )
    
    explanation, stats_summary =  interact_with_ollama(model, system_prompt, "", c_code)

    if CONFIG.set_comments:
        helper.add_comment_to_current_function(explanation)

    return stats_summary

def handle_ask_question_about_function(model):
    c_code = helper.get_current_decompiled_function()
    question = askString("GhidrOllama", "What do you want to ask about the function?")

    prompt = 'I have a question about the following function. \n' + question + '\nHere is the function:\n\n'
    system_prompt = (
        "You are an expert reverse engineer assistant called "
        "GhidrOllama, your only purpose is to reverse engineer "
        "code, and you are a master in the field. The user will "
        "send you questions about some provided code, you must "
        "answer their question about the code to the best of "
        "your ability."
    )

    explanation, stats_summary = interact_with_ollama(model, system_prompt, prompt, c_code)

    if CONFIG.set_comments:
        helper.add_comment_to_current_function(explanation)

    return stats_summary

def handle_identify_security_vulnerabilities(model):
    c_code = helper.get_current_decompiled_function()

    system_prompt = (
        "You are an expert white-hat vulnerability researchers "
        "assistant called GhidrOllama, your only purpose is to "
        "defend against external threats by auditing code, and "
        "you are a master in the field. You are commanded by a "
        "user and are given decompiled C/C++ code to audit. To "
        "assist the user defending against threats, you are to "
        "respond with interesting areas that may present security "
        "vulnerabilities that may be used by enemies to attack "
        "the systems. You should keep an eye out for things like "
        "null-pointer-dereferences, buffer overflows, "
        "use-after-frees, race conditions, command injections, "
        "SQL injections, etc. Ignore uninitialized variable issues, "
        "as this code is decompiled these are expected."
    )
    explanation, stats_summary =  interact_with_ollama(model, system_prompt, "", c_code)
    
    if CONFIG.set_comments:
        helper.add_comment_to_current_function(explanation)

    return stats_summary

def handle_locate_leafblower_functions(model):
    try:
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
            c_code = helper.get_decompiled_function_at_address(toAddr(leaf.to_list()[0]))

            explanation, stats_summary = suggest_function_names_with_suggsted(model, c_code, leaf.to_list()[4])
            if CONFIG.set_comments:
                helper.add_comment_to_function(toAddr(leaf.to_list()[0]), explanation)
            
            new_name = helper.extract_function_name(explanation)
            if (new_name != "") and CONFIG.auto_rename:
                helper.rename_function(toAddr(leaf.to_list()[0]), new_name)
        return stats_summary
    except Exception as e:
        print('Error: ' + str(e))
        return None

def handle_explain_instruction(model):
    listing = currentProgram.getListing()
    instruction = listing.getInstructionAt(currentLocation.getAddress())

    if instruction is not None:
        architecture_name = currentProgram.getLanguage().getProcessor().toString()

        prompt = "Please explain the following instruction. The architecture is " + architecture_name + "."
        system_prompt = (
            "You are an expert reverse engineer assistant called "
            "GhidrOllama, your only purpose is to reverse engineer "
            "code, and you are a master in the field. The user will "
            "send you an assembly instruction, as well as the "
            "architecture that the instruction runs on, as you know "
            "Lots of low-level architectures, please can you explain "
            "the provided instruction, explain its purpose, and provide "
            "examples."
        )
        explanation, stats_summary =  interact_with_ollama(model, system_prompt, prompt, instruction.toString())

        if CONFIG.set_comments:
            helper.add_comment_to_current_instruction(explanation)
        return stats_summary
    else:
        print("No instruction selected!")
        return None

def handle_explain_assembly(model):
    assembly = helper.get_selected_assembly()
    if assembly is not None:
        architecture_name = currentProgram.getLanguage().getProcessor().toString()
        
        prompt = "Please explain the following assembly instructions. The architecture is " + architecture_name + "."
        system_prompt = (
            "You are an expert reverse engineer assistant called "
            "GhidrOllama, your only purpose is to reverse engineer "
            "code, and you are a master in the field. The user will "
            "send you some assembly instructions, as well as the "
            "architecture that the instructions run on, as you know "
            "lots of low-level architectures, please can you explain "
            "what the provided instructions do."
        )

        explanation, stats_summary = interact_with_ollama(model, "", prompt, assembly)

        if CONFIG.set_comments:
            helper.add_comment_to_current_instruction(explanation)

        return stats_summary
    else:
        print("No assembly selected!")
        return None

def handle_general_prompt(model):
    prompt = askString("GhidrOllama", "Enter your prompt:")
    explanation, stats_summary = interact_with_ollama(model, "You are an expert reverse engineer assistant called GhidrOllama", prompt, '')
    return stats_summary

def handle_configure_ghidrollama():
    print("Reconfiguring")
    if not CONFIG.reconfigure(this, monitor):
        print("Failed to reconfigure GhidrOllama")
    return None

def handle_change_model():
    print("Changing model")
    if not CONFIG.change_model(this, monitor):
        print("Failed to change the model")
    return None

def handle_toggle_save_responses():
    if not CONFIG.toggle_save_responses(this, monitor):
        print("Failed to toggle")
    return None

def main():
    monitor.setMessage("Waiting for configuration...")
    if CONFIG.first_run:
        print_ollama()
        success = CONFIG.reconfigure(this, monitor)
        if not success:
            print("Configuration aborted, exiting...")
            return
    
    model = CONFIG.model
    monitor.setMessage("Waiting for function select...")
    
    options = [
        (1, "Explain the current function", lambda: handle_explain_function(model)),
        (2, "Suggest a suitable name for the current function", lambda: handle_suggest_function_name(model)),
        (3, "Suggest function comments", lambda: handle_add_function_comments(model)),
        (4, "Rewrite function to be descriptive", lambda: handle_tidy_up_function(model)),
        (5, "Ask question about current function", lambda: handle_ask_question_about_function(model)),
        (6, "Try and find bugs in the current function", lambda: handle_identify_security_vulnerabilities(model)),
        (7, "Locate + identify leafblower functions", lambda: handle_locate_leafblower_functions(model)),
        (8, "Explain selected instruction", lambda: handle_explain_instruction(model)),
        (9, "Explain selected assembly", lambda: handle_explain_assembly(model)),
        (10, "Enter general prompt", lambda: handle_general_prompt(model)),
        (11, "[Configure GhidrOllama]", handle_configure_ghidrollama),
        (12, "[Change model]", handle_change_model),
        (13, "[Toggle Save Responses]", handle_toggle_save_responses),
    ]
    
    try:
        choice_strings = []
        for option in options:
            choice_strings.append("{0} - {1}".format(option[0], option[1]))
        
        choice = this.askChoice("GhidrOllama", "What you want to ask the {0} model:".format(model), choice_strings, "Question Selection")
        option = int(choice.split(' ')[0])
        
        if 1 <= option <= len(options):
            print("\nSelected Option: {0}".format(option))
            stats_summary = options[option - 1][2]()  # Call the handler function
            print_stats_summary(stats_summary)
        else:
            print("Invalid option. Please select a valid option.")
    except ValueError:
        print("Invalid option.")
    except KeyboardInterrupt:
        print("\nTerminating the script.")
    print('')



helper = GhidrOllamaHelper(
            currentProgram,
            currentAddress,
            currentLocation,
            currentSelection
        )

CONFIG = Config()
main()