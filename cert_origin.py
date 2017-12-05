import os
import time
from itertools import combinations
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


# DATA_DIRECTORY = 'C:/Users/drewr/Documents/Graduate_Files/Classes/ENEE657/leaf_cert/'
DATA_DIRECTORY = '/home/slashzero/Downloads/leaf_cert/'

# setup fingerprinting
fingerprint_filename = r"./classiftable_20160716.csv"  # from https://crocs.fi.muni.cz/public/papers/usenix2016
mask_prob_dict, groups = fingerprint.read_fingerprint_table(fingerprint_filename)

# generate list of all PEM files in directory
pem_files_list = list()
for file in os.listdir(DATA_DIRECTORY):
    if file.endswith(".pem"):
        pem_files_list.append(DATA_DIRECTORY + file)

print("Num of PEM files: " + str(len(pem_files_list)))

# Get statistics about certificates in data set.
# Recorded data:
#   duplicate public keys
#   Issuer's name & organization
#   Number of RSA & DSA keys
pem_certs = get_certs_from_list(pem_files_list)
num_rsa_keys = 0
num_dsa_keys = 0
num_keys_in_each_group = [0] * len(groups)
seen_keys = set()
duplicate_keys = []
unique_keys = []
dict_common_name = dict()
dict_org = dict()
num_certs_with_no_common_name = 0
num_certs_with_no_org_name = 0
key_to_certificate_dict = dict()  # dictionary linking between a public key modulus & the certificate object
for certificate in pem_certs:
    pub_key = certificate.public_key()

    # retrieve common name(issuer) for certs
    if certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME):
        attribute_count(dict_common_name, certificate, "COMMON_NAME")
    else:
        num_certs_with_no_common_name += 1

    if certificate.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME):
        attribute_count(dict_org, certificate, "ORGANIZATION_NAME")
    else:
        num_certs_with_no_org_name += 1

    # count num of RSA and DSA keys
    if isinstance(pub_key, DSAPublicKey):
        num_dsa_keys = num_dsa_keys + 1
    elif isinstance(pub_key, RSAPublicKey):
        num_rsa_keys = num_rsa_keys + 1
        pub_mod = pub_key.public_numbers().n
        if pub_mod not in seen_keys:
            seen_keys.add(pub_mod)
            unique_keys.append(certificate)
            key_to_certificate_dict[pub_mod] = [certificate]
        else:
            duplicate_keys.append(certificate)
            key_to_certificate_dict[pub_mod].append(certificate)
        # todo: Maybe record probability and then normalize at end by number of keys?
        num_keys_in_each_group[groups.index(fingerprint.get_likely_group_from_key(pub_mod, mask_prob_dict, groups))] += 1
        if fingerprint.classify_key(pub_mod, mask_prob_dict, groups)[3] == 100:
            print(pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        raise ValueError

print("Total number of certificates: {0}. ".format(len(pem_certs)))
print("Number of DSA certs = {0}".format(num_dsa_keys))
print("Number of RSA certs = {0}. Number of unique certs: {1}. Number of duplicates: {2} ".format(num_rsa_keys,
                                                                                                  len(unique_keys),
                                                                                                  len(duplicate_keys)))
print("Certificates with no common names: ", num_certs_with_no_common_name)
print("Number of keys per group, assuming taking the most likely group per key:")
print(num_keys_in_each_group)

with open('issuers.txt', 'w') as file:
    for key in sorted(dict_common_name, key=dict_common_name.get, reverse=True):
        file.write("{0}: {1}\n".format(key, dict_common_name[key]))

with open('org.txt', 'w') as file:
    for key in sorted(dict_org, key=dict_org.get, reverse=True):
        file.write("{0}: {1}\n".format(key, dict_org[key]))

certs_with_dup_keys = 0
with open('dupes.txt', 'w') as file:
    for pub_mod in key_to_certificate_dict:
        if len(key_to_certificate_dict[pub_mod]) > 1:
            certs_with_dup_keys += len(key_to_certificate_dict[pub_mod]) - 1
            for i in range(len(key_to_certificate_dict[pub_mod])):
                file.write(certs_with_dup_keys[pub_mod][i].issuer.get_attributes_for_oid(getattr(NameOID, "COMMON_NAME"))[0].value)
                file.write(", ")
            file.write("\n")

print("Certs with dup keys: ", certs_with_dup_keys)

changed_issuer_dict = dict()
validity_overlap_dict = dict()
num_changed_issuers = 0
num_overlap_validity = 0
for pub_mod in key_to_certificate_dict:
    if len(key_to_certificate_dict[pub_mod]) > 1:
        current_cert_list = key_to_certificate_dict[pub_mod]
        changes_list = list()
        validity_list = list()
        for cert_a, cert_b in combinations(current_cert_list, 2):
            assert isinstance(cert_a, x509.Certificate)
            assert isinstance(cert_b, x509.Certificate)
            # for n in NameOID:
            # check if issuer has changed
            if cert_a.issuer is not cert_b.issuer:
                changes_list.append((cert_a, cert_b))

            # check if overlap between validity of certificates
            if (cert_a.not_valid_before < cert_b.not_valid_after) or \
                    (cert_b.not_valid_before < cert_a.not_valid_before):
                validity_list.append((cert_a, cert_b))

        if len(changes_list) > 0:
            changed_issuer_dict[pub_mod] = changes_list
            num_changed_issuers += 1
        if len(validity_list) > 0:
            validity_overlap_dict[pub_mod] = validity_list
            num_overlap_validity += 1

print("Found {0} changed issuers and {1} overlapping validity instances".format(num_changed_issuers,
                                                                                num_overlap_validity))

print(groups)
