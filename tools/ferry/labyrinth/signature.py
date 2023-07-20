import subprocess


class Searcher(object):
    """
    Case-insensitive search for function signatures in all elf objects
    """

    def __init__(self, project):
        self.project = project

    def get_any_signature(self, function):
        result = None
        for elf in self.project.loader.all_elf_objects:
            for (k, v) in elf.demangled_names.items():
                if v.find(function) != -1:
                    result = (v, k)
                    break
        return result

    def get_all_signatures(self, function):
        result = []
        for elf in self.project.loader.all_elf_objects:
            for (k, v) in elf.demangled_names.items():
                if v.find(function) != -1:
                    result.append((v, k))
        return result


class Parser(object):
    @staticmethod
    def get_demangled_name(name):
        """
        The name of this symbol, run through a C++ demangler
        Warning: this calls out to the external program `c++filt` and will fail loudly if it's not installed
        """
        # make sure it's mangled
        if name.startswith("_Z"):
            if '@@' in name:
                name = name.split("@@")[0]
            args = ['c++filt']
            args.append(name)
            pipe = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            stdout, _ = pipe.communicate()
            demangled = stdout.split("\n")

            if demangled:
                return demangled[0]

        return name

    @staticmethod
    def get_demangled_name_without_params(name):
        """
        The name of this symbol, run through a C++ demangler
        Warning: this calls out to the external program `c++filt` and will fail loudly if it's not installed
        """
        # make sure it's mangled
        if name.startswith("_Z"):
            if '@@' in name:
                name = name.split("@@")[0]
            args = ['c++filt', '-p']
            args.append(name)
            pipe = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            stdout, _ = pipe.communicate()
            demangled = stdout.split("\n")

            if demangled:
                return demangled[0]

        return name

    @staticmethod
    def get_argument_count(name):
        full_name = Parser.get_demangled_name(name)
        func_name = Parser.get_demangled_name_without_params(name)
        args = full_name.replace(func_name, '')
        if not args or args.find('()') != -1:
            return 0

        return len(args.split(','))
