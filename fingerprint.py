import csv
import re

import numpy as np

import moduloparse as mp

"""
This script implements RSA key fingerprinting as described at https://crocs.fi.muni.cz/public/papers/usenix2016.
Essentially, given a list of keys and a pre-computed probability lookup table, will compute the most likely
key generation algorithm that was used to compute the RSA public key.
"""

fingerprint_filename = r"./classiftable_20160716.csv"  # from https://crocs.fi.muni.cz/public/papers/usenix2016
public_moduli_filename = r"vulnerable_moduli_all_keys_not_parallel_without_repeats"  # filename with moduli to be parsed


# read in fingerprints to a dictionary
mask_to_prob_dict = dict()
group_names = list()  # list of group names that can be classified
with open(fingerprint_filename, 'r') as finger_file:
    has_header = csv.Sniffer().has_header(finger_file.read(1024))
    finger_file.seek(0)  # rewind
    finger_csv_reader = csv.reader(finger_file, delimiter=';', lineterminator='; \r\n')
    if has_header:
        # Store group names
        first_row = next(finger_csv_reader)
        group_names = first_row[1:]
        group_names.remove('')
        group_names = [name.strip() for name in group_names]

    for row in finger_csv_reader:
        # store all probabilities as dictionary, with the mask corresponding to a probability vector
        stripped_row = [re.sub('-', '0.0', column.strip()) for column in row]
        stripped_row.remove('')
        key = stripped_row[0]
        probability_vector = np.array([float(val) for val in stripped_row[1:]])
        mask_to_prob_dict[key] = probability_vector

all_1s = np.ones((1, len(group_names)))
equal_weighting = all_1s / np.linalg.norm(all_1s)


# read in keys.
# read_key_masks = list()
# list of strings of binary numbers. Each string follows format "XXXXXX|X|X|X"
# This format denotes computations from the RSA public key. Format:
# "2nd-7th MSB of key modulus|2nd LSB of key modulus|key modulus modulo 3|modulus length in bits modulo 2"
read_key_masks = mp.get_mask_strings(public_moduli_filename, False)


# for each key, look up appropriate entry in dictionary. Compute likely group that given keys belong to in this
# read_key_masks = ["000101|0|1|0", "000010|0|1|0"] # used for testing
total_prob = np.array([])
for key_mask in read_key_masks:
    if key_mask in mask_to_prob_dict.keys():
        arr = mask_to_prob_dict[key_mask]
        if len(total_prob) is 0:
            total_prob = arr
        else:
            total_prob = total_prob * arr
    else:
        if len(total_prob) == 0:
            total_prob = equal_weighting
        else:
            total_prob = total_prob * equal_weighting

# normalize probability vector (assuming numpy array)
norm_prob = total_prob / np.linalg.norm(total_prob)

max_index = np.argmax(norm_prob)  # find index of the maximum normalized probability
decided_group = group_names[int(max_index)]

print("Note: Following probability can be incorrect if any key was 100% in one category.")
print("Classified the keys into: " + decided_group + " with probability " +
      '{:02.1f}%'.format(norm_prob[0][max_index] * 100))
