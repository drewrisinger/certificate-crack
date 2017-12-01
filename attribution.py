import os
import time
from typing import List

import numpy as np
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

import fingerprint


def get_certs_from_list(cert_filenames: List[str]):
    """
    Function to return a list of x509 certificates given a list of files
    :param cert_filenames:
    :return:
    """
    certs_list = list()
    start_time = time.perf_counter()
    for filename in cert_filenames:
        with open(filename, 'rb') as f:
            certs_list.append(x509.load_pem_x509_certificate(f.read(), default_backend()))
        if len(certs_list) % 25000 == 0:
            print("{0} x509 loaded in {1} seconds".format(str(len(certs_list)), str(time.perf_counter() - start_time)))

    stop_time = time.perf_counter()
    print("Certs loaded per second: " + str(len(certs_list) / (stop_time - start_time)))

    return certs_list


DATA_DIRECTORY = 'C:/Users/drewr/Documents/Graduate_Files/Classes/ENEE657/leaf_cert/'

# setup fingerprinting
fingerprint_filename = r"./classiftable_20160716.csv"  # from https://crocs.fi.muni.cz/public/papers/usenix2016
mask_prob_dict, groups = fingerprint.read_fingerprint_table(fingerprint_filename)

test_file = DATA_DIRECTORY + "00a0af20e171dc_1" + ".pem"

# test reading just one certificate
with open(test_file, 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read(), default_backend())

print(cert)

# generate list of all PEM files in directory
pem_files_list = list()
for file in os.listdir(DATA_DIRECTORY):
    if file.endswith(".pem"):
        pem_files_list.append(DATA_DIRECTORY + file)

print("Num of PEM files: " + str(len(pem_files_list)))

# read list of vulnerable files from file
vuln_files = list()
with open('./possible_vulnerable_files.txt', 'r') as f:
    for name in f.readlines():
        vuln_files.append(DATA_DIRECTORY + name.strip())

# read certificates into list
vuln_certs = get_certs_from_list(vuln_files)
print(len(vuln_certs))

for c in vuln_certs:
    pub_key = c.public_key()
    if isinstance(pub_key, DSAPublicKey):
        # pub_mod = pub_key.public_numbers().y
        print("Issue: given certificate is a DSA, not RSA, key.")
    elif isinstance(pub_key, RSAPublicKey):
        pub_mod = pub_key.public_numbers().n
        print(
            "Key is probably from group: {0}".format(fingerprint.get_likely_group_key(pub_mod, mask_prob_dict, groups)))
    else:
        raise ValueError

pem_certs = get_certs_from_list(pem_files_list)
num_rsa = 0
num_dsa = 0
num_per_group = [0] * len(groups)
total_prob = np.zeros(len(groups))
for c in pem_certs:
    pub_key = c.public_key()
    if isinstance(pub_key, DSAPublicKey):
        num_dsa = num_dsa + 1
    elif isinstance(pub_key, RSAPublicKey):
        num_rsa = num_rsa + 1
        # todo: Maybe record probability and then normalize at end by number of keys?
        pub_mod = pub_key.public_numbers().n
        num_per_group[groups.index(fingerprint.get_likely_group_key(pub_mod, mask_prob_dict, groups))] += 1
        total_prob += fingerprint.classify_key(pub_mod, mask_prob_dict, groups)
    else:
        raise ValueError

print("Number of RSA certs = {0}. Number of DSA certs = {1}".format(num_rsa, num_dsa))
print("Number of keys per group, assuming taking the most likely group per key:")
print(num_per_group)

norm_prob = total_prob / np.linalg.norm(total_prob)
print(norm_prob)
