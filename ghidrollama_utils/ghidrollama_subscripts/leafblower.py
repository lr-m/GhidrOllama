from . import utils

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import RefType
from ghidra.program.model.block import BasicBlockModel


def get_argument_registers(current_program):
    """
    Get argument registers based on processor type.

    :param current_program: Ghidra program object.
    :type current_program: ghidra.program.model.listing.Program

    :returns: List of argument registers.
    :rtype: list(str)
    """
    arch = utils.get_processor(current_program)

    if arch == 'MIPS':
        return ['a0', 'a1', 'a2', 'a3']
    elif arch == 'ARM':
        return ['r0', 'r1', 'r2', 'r3']
    return []


class Function(object):
    CANDIDATES = {}

    def __init__(self, function, candidate_attr, has_loop=None,
                 argument_count=-1, format_arg_index=-1):

        self.name = function.getName()
        self.address = function.getEntryPoint()
        self.xref_count = function.getSymbol().getReferenceCount()
        self.has_loop = has_loop
        self.argument_count = argument_count
        self.format_arg_index = format_arg_index
        self.candidates = []
        if candidate_attr in self.CANDIDATES:
            self.candidates = self.CANDIDATES[candidate_attr]


class LeafFunction(Function):
    """
    Class to hold leaf function candidates.
    """

    CANDIDATES = {
        1: ['atoi', 'atol', 'strlen'],
        2: ['strcpy', 'strcat', 'strcmp', 'strstr', 'strchr', 'strrchr',
            'bzero'],
        3: ['strtol', 'strncpy', 'strncat', 'strncmp', 'memcpy', 'memmove',
            'bcopy', 'memcmp', 'memset']
    }

    def __init__(self, function, has_loop, argument_count):
        super(LeafFunction, self).__init__(
            function, argument_count, has_loop, argument_count)

    def to_list(self):
        return [self.address.toString(), self.name, str(self.xref_count), str(self.argument_count),
                ','.join(self.candidates)]

    @classmethod
    def is_candidate(cls, function, has_loop, argument_count):
        """
        Determine is a function is a candidate for a leaf function. Leaf 
        functions must have loops, make no external calls, require 1-3 
        arguments, and have a reference count greater than 25. 
        """
        if not has_loop:
            return False

        if argument_count > 3 or argument_count == 0:
            return False

        if function.getSymbol().getReferenceCount() < 25:
            return False

        return True


class FormatFunction(Function):
    """
    Class to hold format string function candidates.
    """

    CANDIDATES = {
        0: ['printf'],
        1: ['sprintf', 'fprintf', 'fscanf', 'sscanf'],
        2: ['snprintf']
    }

    def __init__(self, function, format_arg_index):
        super(FormatFunction, self).__init__(
            function, format_arg_index, format_arg_index=format_arg_index)

    def to_list(self):
        return [self.address, self.name, str(self.xref_count), str(self.format_arg_index),
                ','.join(self.candidates)]


class FinderBase(object):
    def __init__(self, program):
        self._program = program
        self._flat_api = FlatProgramAPI(program)
        self._monitor = self._flat_api.getMonitor()
        self._basic_blocks = BasicBlockModel(self._program)

    def _display(self, title, entries):
        """
        Print a simple table to the terminal.

        :param title: Title of the table.
        :type title: list

        :param entries: Entries to print in the table.
        :type entries: list(list(str))
        """
        lines = [title] + entries

        # Find the largest entry in each column so it can be used later
        # for the format string.
        max_line_len = []
        for i in range(0, len(title)):
            column_lengths = [len(line[i]) for line in lines]
            max_line_len.append(max(column_lengths))

        # Account for largest entry, spaces, and '|' characters on each line.
        separator = '=' * (sum(max_line_len) +
                           (len(title) * (len(title) - 1))
                           + 1)
        spacer = '|'
        format_specifier = '{:<{width}}'

        # First block prints the title and '=' characters to make a title
        # border
        print separator
        print spacer,
        for width, column in zip(max_line_len, title):
            print format_specifier.format(column, width=width),
            print spacer,
        print ''
        print separator

        # Print the actual entries.
        for entry in entries:
            print spacer,
            for width, column in zip(max_line_len, entry):
                print format_specifier.format(column, width=width),
                print spacer,
            print ''
        print separator


class LeafFunctionFinder(FinderBase):
    """
    Leaf function finder class. 
    """

    def __init__(self, program):
        super(LeafFunctionFinder, self).__init__(program)
        self.leaf_functions = []
        
    def get_leaves(self):
        return self.leaf_functions

    def find_leaves(self):
        """
        Find leaf functions. Leaf functions are functions that have loops,
        make no external calls, require 1-3 arguments, and have a reference 
        count greater than 25.
        """
        function_manager = self._program.getFunctionManager()

        for function in function_manager.getFunctions(True):
            if not self._function_makes_call(function):
                loops = self._function_has_loops(function)
                argc = self._get_argument_count(function)

                if LeafFunction.is_candidate(function, loops, argc):
                    self.leaf_functions.append(LeafFunction(function,
                                                            loops,
                                                            argc))

        self.leaf_functions.sort(key=lambda x: x.xref_count, reverse=True)

    def display(self):
        """
        Print leaf function candidates to the terminal.
        """
        title = ['Address', 'Function', 'XRefs', 'Args', 'Potential Function']
        leaf_list = [leaf.to_list() for leaf in self.leaf_functions]

        self._display(title, leaf_list)

    def _function_makes_call(self, function):
        """
        Determine if a function makes external calls.

        :param function: Function to inspect.
        :type function: ghidra.program.model.listing.Function

        :returns: True if the function makes external calls, False otherwise.
        :rtype: bool
        """
        function_body = function.getBody()
        min_addr = function_body.minAddress
        max_addr = function_body.maxAddress

        curr_addr = min_addr
        while curr_addr <= max_addr:
            instruction = self._flat_api.getInstructionAt(curr_addr)
            if utils.is_call_instruction(instruction):
                return True
            curr_addr = curr_addr.next()
        return False

    def _function_has_loops(self, function):
        """
        Determine if a function has internal loops.

        :param function: Function to inspect.
        :type function: ghidra.program.model.listing.Function

        :returns: True if the function has loops, False otherwise.
        :rtype: bool
        """

        function_blocks = self._basic_blocks.getCodeBlocksContaining(
            function.body, self._monitor)

        while function_blocks.hasNext():
            block = function_blocks.next()
            destinations = block.getDestinations(self._monitor)

            # Determine if the current block can result in jumping to a block
            # above the end address and in the same function. This indicates
            # an internal loop.
            while destinations.hasNext():
                destination = destinations.next()
                dest_addr = destination.getDestinationAddress()
                destination_function = self._flat_api.getFunctionContaining(
                    dest_addr)
                if destination_function == function and \
                        dest_addr <= block.minAddress:
                    return True
        return False

    def _get_argument_count(self, function):
        """
        Determine the argument count to the function. This is determined by 
        inspecting argument registers to see if they are read from prior to 
        being written to.

        :param function: Function to inspect.
        :type function: ghidra.program.model.listing.Function

        :returns: Argument count.
        :rtype: int
        """
        used_args = []
        arch_args = get_argument_registers(self._program)

        min_addr = function.body.minAddress
        max_addr = function.body.maxAddress

        curr_ins = self._flat_api.getInstructionAt(min_addr)

        while curr_ins and curr_ins.getAddress() < max_addr:
            for op_index in range(0, curr_ins.getNumOperands()):
                ref_type = curr_ins.getOperandRefType(op_index)
                # We only care about looking at reads and writes. Reads that
                # include and index into a register show as 'data' so look
                # for those as well.
                if ref_type not in [RefType.WRITE, RefType.READ, RefType.DATA]:
                    continue

                # Check to see if the argument is an argument register. Remove
                # that register from the arch_args list so it can be ignored
                # from now on. If reading from the register add it to the
                # used_args list so we know its a used parameter.
                operands = curr_ins.getOpObjects(op_index)
                for operand in operands:
                    op_string = operand.toString()
                    if op_string in arch_args:
                        arch_args.remove(op_string)
                        if ref_type in [RefType.READ, RefType.DATA]:
                            used_args.append(op_string)
            curr_ins = curr_ins.next

        return len(used_args)

