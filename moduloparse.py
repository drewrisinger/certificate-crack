import sys

"""
This script parses a set of moduli from an input file and generates a list of strings, one for each moduli. Each string
contains the following information:
    1. The MSB 2-7 bits
    2. The 2nd LSB
    3. The modulus modulo 3
    4. The modulus length modulo 2

"""


def mod_parser(moduli_filename):
    # read name and modulus to a dictionary
    mod_n_name = dict()
    with open(moduli_filename, 'r') as mod_file:
        mod_list = mod_file.readlines()
        for fileName, modulus in zip(mod_list[::2], mod_list[1::2]):
            fileName.strip()
            modulus.strip()
            modulus = int(modulus, 16)
            if modulus in mod_n_name:
                mod_n_name[modulus].append(fileName)
            else:
                mod_n_name[modulus] = [fileName]
    return mod_n_name


class PublicKeyModulus:
    """Common class for all modulus"""
    modulus_count = 0

    def __init__(self, modulus):
        self.modulus = modulus
        self.length = len(bin(self.modulus)) - 2
        PublicKeyModulus.modulus_count += 1

    def get_lsb2(self):
        return self.modulus >> 1 & 1

    def get_length(self):
        return len(bin(self.modulus)) - 2

    def get_2_7(self):
        return self.modulus >> (self.length - 2) & 0b111111

    def get_mod3(self):
        return self.modulus % 3

    def get_len_mod2(self):
        return self.length % 2

    def get_req_values(self):
        return ("{0:06b}".format(self.get_2_7()) + "|" + "{0:b}".format(self.get_lsb2()) + "|" + str(self.get_mod3()) +
                "|" + str(self.get_len_mod2()))


def get_needed_values(moduli_filename):
    mod_n_name = mod_parser(moduli_filename)
    mod_list = [PublicKeyModulus(mod) for mod in mod_n_name]
    req_strings = [mod.get_req_values() for mod in mod_list]
    return req_strings


def main():
    # moduli_filename = r"./names_and_modulus.txt"
    moduli_filename = sys.argv[1]
    req_strings = get_needed_values(moduli_filename)
    for string in req_strings:
        print(string)


if __name__ == "__main__":
    main()
