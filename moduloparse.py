import sys

from typing import Dict, List
"""
This script parses a set of moduli from an input file and generates a list of strings, one for each moduli. Each string
contains the following information:
    1. The MSB 2-7 bits
    2. The 2nd LSB
    3. The modulus modulo 3
    4. The modulus length modulo 2

"""


def mod_parser(moduli_filename: str, includes_filenames: bool = True) -> Dict[int, str]:
    # read name and modulus to a dictionary
    """
    Generates dictionary of moduli:filename given a file in format [filename\n modulus]*repetitions.
    :param moduli_filename: File reference with the moduli.
    :param includes_filenames: True if the file includes filenames, or just moduli
    :return: Dictionary of moduli and corresponding filename. filename = None if includes_filesnames = False
    """
    mod_n_name = dict()
    with open(moduli_filename, 'r') as mod_file:
        mod_list = mod_file.readlines()
        if includes_filenames:
            for fileName, modulus in zip(mod_list[::2], mod_list[1::2]):
                fileName.strip()
                modulus.strip()
                modulus = int(modulus, 16)
                if modulus in mod_n_name:
                    mod_n_name[modulus].append(fileName)
                else:
                    mod_n_name[modulus] = [fileName]
        else:
            for modulus in mod_list:
                modulus.strip()
                modulus = int(modulus, 16)
                mod_n_name[modulus] = None
    return mod_n_name


class PublicKeyModulus:
    """Common class for all modulus"""
    modulus_count = 0

    def __init__(self, modulus: int):
        """
        Constructor for PublicKeyModulus. Created based on the modulus of a public key
        :param modulus: int representing a modulus for an RSA public key.
        """
        self.modulus = modulus
        self.length = len(bin(self.modulus)) - 2
        PublicKeyModulus.modulus_count += 1

    def get_lsb2(self) -> int:
        """
        Gets the 2nd least significant bit of the public key modulus
        :return: bit representing the 2nd LSB of the key
        """
        return self.modulus >> 1 & 0b1

    def get_length(self) -> int:
        """
        Gets the length of the public key modulus in bits
        :return: len(modulus) in bits
        """
        return len(bin(self.modulus)) - 2

    def get_2_7(self) -> int:
        """"
        Get 2nd->7th most significant bit of public key modulus
        """
        return self.modulus >> (self.length - 7) & 0b111111

    def get_mod3(self) -> int:
        """
        Gets the RSA public key (i.e. the modulus) modulo 3
        :return: key modulo 3
        """
        return self.modulus % 3

    def get_len_mod2(self) -> int:
        """
        Returns the length of the public key modulus 2
        :return: len(key) in bits % 2
        """
        return self.length % 2

    @property
    def get_req_values(self) -> str:
        """
        Gets a string with the mask values of the public key modulus.
        :return: str in format MSB2-7|2ndLSB|key%3|len(key)%2
        """
        return ("{0:06b}".format(self.get_2_7()) + "|" + "{0:b}".format(self.get_lsb2()) + "|" + str(self.get_mod3()) +
                "|" + str(self.get_len_mod2()))


def get_mask_strings(moduli_filename: str, includes_filenames: bool = True) -> List[str]:
    """
    Gets the mask strings representing the public keys in a file
    :param moduli_filename: File reference that includes the public key moduli
    :param includes_filenames: whether the file includes filenames or not
    :return: list[str] with public key masks, as described in https://crocs.fi.muni.cz/public/papers/usenix2016
    """
    mod_n_name = mod_parser(moduli_filename, includes_filenames)
    mod_list = [PublicKeyModulus(mod) for mod in mod_n_name]
    req_strings = [mod.get_req_values for mod in mod_list]
    return req_strings


def main():
    # moduli_filename = r"./names_and_modulus.txt"
    moduli_filename = sys.argv[1]
    req_strings = get_mask_strings(moduli_filename)
    for string in req_strings:
        print(string)


if __name__ == "__main__":
    main()
