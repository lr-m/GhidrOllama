import os
import json
import shutil
from ghidra.util.exception import CancelledException
from ghidra.util.task import TaskMonitor
import urllib2

class Config:
    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
    CONFIG_FILE_PATH = os.path.join(SCRIPT_DIR, "ghidrollama_config.json")
    
    def __init__(self, script):
        self.script = script
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
    def select_model(script, scheme, host, port):
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

            choice = script.askChoice("GhidrOllama", "Please choose the model you want to use:", model_names, "Model Selection")

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


    def reconfigure(self, monitor):
        """
        Guide the user through setting new configuration values.
        """
        # Get hostname
        monitor.setMessage("Waiting for hostname")
        try:
            host = self.script.askString("GhidrOllama", "Please enter the hostname or IP of your server:", "localhost")
        except CancelledException:
            return False
        print("Selected host: " + host)
        if host == None:
            return False

        # Get port (if nothing entered, assume 11434 as default)
        monitor.setMessage("Waiting for port")
        try:
            port = self.script.askInt("GhidrOllama", "Please enter the port number of your server [1-65535, usually 11434]:")
        except CancelledException:
            return False
        
        if port == 0 or port == None:
            port = 11434

        print("Selected port: " + str(port))

        # Get scheme
        monitor.setMessage("Waiting for model select...")
        try:
            scheme = self.script.askChoice("GhidrOllama", "Please choose the scheme your server uses:", ["http", "https"], "http")
        except CancelledException:
            return False
        print("Selected scheme: " + scheme)
        if scheme == None:
            return False

        # Get model
        monitor.setMessage("Waiting for model select...")
        try:
            model = Config.select_model(self.script, scheme, host, port)
        except CancelledException:
            return False
        print("Selected model: " + model)

        if model == None:
            return False

        # Get project-specific prompt/context if desired.
        monitor.setMessage("Waiting for project-specific prompt...")
        try:
            prompt = self.script.askString("Project Prompt", "Please enter a project-specific prompt to prepend to all queries, or leave blank (space):", " ")
            if prompt == None or prompt == " ":
                prompt = ""
        except CancelledException:
            return False

        try:
            set_comments = self.script.askYesNo("Set Comments", "Would you like query responses to be stored as function comments?")
        except CancelledException:
            return False
            
        try:
            auto_rename = self.script.askYesNo("Auto Renaming", "Would you like GhidrOllama to try and automatically rename functions based on responses?")
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


    def change_model(self, monitor):
        """Change the configured model and persist the change.
        Return true on success."""

        monitor.setMessage("Waiting for model select...")
        try:
            model = Config.select_model(self.script, self.scheme, self.host, self.port)
        except CancelledException:
            return False

        print("Selected model: " + model)
        self.model = model
        self.config["model"] = model
        self.save()
        return True

    
    def toggle_save_responses(self, monitor):
        try:
            set_comments = self.script.askYesNo("Set Comments", "Would you like query responses to be stored as comments?")
        except CancelledException:
            return False

        self.set_comments = set_comments
        self.config["set_comments"] = set_comments 

        if set_comments:
            print("Save responses as comments enabled")
        else:
            print("Save responses as comments disabled")

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