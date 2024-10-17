import re
from ghidra.util.task import TaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

class GhidrOllamaHelper:
    def __init__(self, current_program, current_address, current_location, current_selection):
        self.current_program = current_program
        self.current_address = current_address
        self.current_location = current_location
        self.current_selection = current_selection
        self.flat_api = None  # Initialize in a method if needed


    def add_comment_to_current_function(self, comment):
        current_function = self.get_function_containing(self.current_address)
        current_function.setComment(comment)


    def add_comment_to_function(self, address, comment):
        current_function = self.get_function_containing(address)
        current_function.setComment(comment)


    def add_comment_to_current_instruction(self, comment_text):
        instruction = self.current_program.getListing().getInstructionAt(self.current_address)
        if instruction is not None:
            self.current_program.getListing().setComment(instruction.getAddress(), CodeUnit.PLATE_COMMENT, comment_text)
            print("Comment added to the instruction at address: {}".format(instruction.getAddress()))
        else:
            print("No instruction found at the current address.")


    def rename_function(self, address, new_name):
        current_function = self.get_function_containing(address)
        current_function.setName(new_name, SourceType.ANALYSIS)


    @staticmethod
    def extract_function_name(explanation):
        regex_result = re.search(r'`(.*)`', explanation)
        if regex_result is None:
            return explanation.split(' ')[0]
        else:
            return regex_result.group(1).split(' ')[0]


    def get_current_decompiled_function(self):
        monitor = TaskMonitor.DUMMY
        decompiler = DecompInterface()
        decompiler.openProgram(self.current_program)
        function = self.get_function_containing(self.current_address)
        if function is None:
            raise ValueError("No function is currently selected.")
        try:
            return decompiler.decompileFunction(function, 30, monitor).getDecompiledFunction().getC()
        except Exception as e:
            raise ValueError("Unable to decompile function: {}".format(e))


    def get_decompiled_function_at_address(self, address):
        monitor = TaskMonitor.DUMMY
        decompiler = DecompInterface()
        decompiler.openProgram(self.current_program)
        function = self.get_function_containing(address)
        if function is None:
            raise ValueError("No function is currently selected.")
        try:
            return decompiler.decompileFunction(function, 30, monitor).getDecompiledFunction().getC()
        except Exception as e:
            raise ValueError("Unable to decompile function: {}".format(e))


    def get_selected_assembly(self):
        instructions = ""
        listing = self.current_program.getListing()
        if self.current_selection is not None:
            for address in self.current_selection.getAddresses(True):
                instruction = listing.getInstructionAt(address)
                if instruction:
                    instructions += '0x{}: {}\n'.format(address.toString(), instruction.toString())
            return instructions
        else:
            return None


    def get_function_containing(self, address):
        if self.flat_api is None:
            from ghidra.program.flatapi import FlatProgramAPI
            self.flat_api = FlatProgramAPI(self.current_program)
        return self.flat_api.getFunctionContaining(address)


# Print ASCII art Llama (essential)
def print_ollama():
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


def print_stats_summary(stats_summary):
    if stats_summary is not None:
        print("\n\n>> Stats Summary:")
        for key, value in stats_summary.items():
            print(" {}: {}".format(key, value))