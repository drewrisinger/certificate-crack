import csv
import re as re

import numpy as np

"""
This script implements RSA key fingerprinting as described at https://crocs.fi.muni.cz/public/papers/usenix2016.
Essentially, given a list of keys and a pre-computed probability lookup table, will compute the most likely
key generation algorithm that was used to compute the RSA public key.
"""

fingerprint_filename = r"./classiftable_20160716.csv"  # from https://crocs.fi.muni.cz/public/papers/usenix2016
public_moduli_filename = r"./moduli"  # filename with moduli to be parsed. TODO: change.

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

# read in keys.
read_key_masks = list()  # list of strings of binary numbers. Each string follows format "XXXXXX|X|X|X"
# This format denotes computations from the RSA public key. Format:
# "2nd-7th MSB of key modulus|2nd LSB of key modulus|key modulus modulo 3|modulus length in bits modulo 2"
# todo: someone else working on this part.

# for each key, look up appropriate entry in dictionary. Compute likely group that given keys belong to in this
# read_key_masks = ["000101|0|1|0", "000010|0|1|0"] # used for testing
total_prob = np.array([])
for key_mask in read_key_masks:
    arr = mask_to_prob_dict[key_mask]
    if len(total_prob) is 0:
        total_prob = arr
    else:
        total_prob = total_prob * arr

# normalize probability vector (assuming numpy array)
norm_prob = total_prob / np.linalg.norm(total_prob)

max_index = np.argmax(norm_prob)  # find index of the maximum normalized probability
decided_group = group_names[int(max_index)]

print("Classified the keys into: " + decided_group)
