import os
import time
from typing import List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.oid import NameOID

import fingerprint

"""
This program tries to analyse the certificates and gather useful data
"""


def get_certs_from_list(cert_filenames: List[str]):
    """Function to return a list of x509 certificates given a list of files
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


# DATA_DIRECTORY = 'C:/Users/drewr/Documents/Graduate_Files/Classes/ENEE657/leaf_cert/'
DATA_DIRECTORY = '/home/slashzero/Downloads/leaf_cert/'

# setup fingerprinting
fingerprint_filename = r"./classiftable_20160716.csv"  # from https://crocs.fi.muni.cz/public/papers/usenix2016
mask_prob_dict, groups = fingerprint.read_fingerprint_table(fingerprint_filename)

test_file = DATA_DIRECTORY + "00a0af20e171dc_1" + ".pem"

# # test reading just one certificate
# with open(test_file, 'rb') as f:
#     cert = x509.load_pem_x509_certificate(f.read(), default_backend())
#
# for attribute in cert.issuer:
#     print(attribute)
#
# print(cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)

# generate list of all PEM files in directory
pem_files_list = list()
for file in os.listdir(DATA_DIRECTORY):
    if file.endswith(".pem"):
        pem_files_list.append(DATA_DIRECTORY + file)

print("Num of PEM files: " + str(len(pem_files_list)))


# # read list of vulnerable files from file
# vuln_files = list()
# with open('./possible_vulnerable_files.txt', 'r') as f:
#     for name in f.readlines():
#         vuln_files.append(DATA_DIRECTORY + name.strip())
#
# # read certificates into list
# vuln_certs = get_certs_from_list(vuln_files)
# print(len(vuln_certs))
#
# for c in vuln_certs:
#     pub_key = c.public_key()
#     if isinstance(pub_key, DSAPublicKey):
#         # pub_mod = pub_key.public_numbers().y
#         print("Issue: given certificate is a DSA, not RSA, key.")
#     elif isinstance(pub_key, RSAPublicKey):
#         pub_mod = pub_key.public_numbers().n
#         print(
#           "Key is probably from group: {0}".format(fingerprint.get_likely_group_key(pub_mod, mask_prob_dict, groups)))
#     else:
#         raise ValueError


def attribute_count(common_names: dict, cert, attribute: str) -> None:
    """
    This function parses certificates and updates a dictionary containing attribute values and their frequencies
    :param common_names: dictionary containing attribute values
    :param cert: certificate to be analyzed
    :param attribute: attribute to be processed
    """
    if cert.issuer.get_attributes_for_oid(getattr(NameOID, attribute))[0].value in common_names:
        common_names[cert.issuer.get_attributes_for_oid(getattr(NameOID, attribute))[0].value] += 1
    else:
        common_names[cert.issuer.get_attributes_for_oid(getattr(NameOID, attribute))[0].value] = 1


pem_certs = get_certs_from_list(pem_files_list)
num_rsa = 0
num_dsa = 0
num_per_group = [0] * len(groups)
seen = set()
duplicate = []
unique = []
dict_common_name = dict()
dict_org = dict()
certs_with_no_common_name = 0
certs_with_no_org_name = 0
certs_with_key = dict()
for c in pem_certs:
    pub_key = c.public_key()
    # retrieving common name(issuer) for certs
    # if c.issuer.get_attributes_for_oid(NameOID.COMMON_NAME):
    #     attribute_count(dict_common_name, c, "COMMON_NAME")
    # else:
    #     certs_with_no_common_name += 1
    # if c.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME):
    #     attribute_count(dict_org, c, "ORGANIZATION_NAME")
    # else:
    #     certs_with_no_org_name += 1
    # counting no of RSA and DSA keys
    if isinstance(pub_key, DSAPublicKey):
        num_dsa = num_dsa + 1
    elif isinstance(pub_key, RSAPublicKey):
        num_rsa = num_rsa + 1
        pub_mod = pub_key.public_numbers().n
        if pub_mod not in seen:
            seen.add(pub_mod)
            unique.append(c)
            certs_with_key[pub_mod] = [c]
        else:
            duplicate.append(c)
            certs_with_key[pub_mod].append(c)
        # todo: Maybe record probability and then normalize at end by number of keys?
        num_per_group[groups.index(fingerprint.get_likely_group_from_key(pub_mod, mask_prob_dict, groups))] += 1
        if fingerprint.classify_key(pub_mod, mask_prob_dict, groups)[3] == 100:
            print(pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        raise ValueError

print("Total number of certificates: {0}. ".format(len(pem_certs)))
print("Number of DSA certs = {0}".format(num_dsa))
print("Number of RSA certs = {0}. Number of unique certs: {1}. Number of duplicates: {2} ".format(num_rsa, len(unique),
                                                                                                  len(duplicate)))
print("Certificates with no common names: ", certs_with_no_common_name)
print("Number of keys per group, assuming taking the most likely group per key:")
print(num_per_group)

with open('issuers.txt', 'w') as file:
    for key in sorted(dict_common_name, key=dict_common_name.get, reverse=True):
        file.write("{0}: {1}\n".format(key, dict_common_name[key]))

with open('org.txt', 'w') as file:
    for key in sorted(dict_org, key=dict_org.get, reverse=True):
        file.write("{0}: {1}\n".format(key, dict_org[key]))

certs_with_dup_keys = 0
with open('dupes.txt', 'w') as file:
    for pub_mod in certs_with_key:
        if len(certs_with_key[pub_mod]) > 1:
            certs_with_dup_keys += len(certs_with_key[pub_mod]) - 1
            for i in range(len(certs_with_key[pub_mod])):
                file.write(
                    certs_with_key[pub_mod][i].issuer.get_attributes_for_oid(getattr(NameOID, "COMMON_NAME"))[0].value)
                file.write(
                    certs_with_key[pub_mod][i].not_valid_after.strftime("%B %d, %Y"))
                file.write(", ")
            file.write("\n")

print("Certs with dup keys: ", certs_with_dup_keys)

print(groups)
