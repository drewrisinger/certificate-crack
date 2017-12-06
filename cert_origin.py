from itertools import combinations

from cryptography import x509
from cryptography.x509.oid import NameOID

import fingerprint
from certificate_analysis import certificate_validity_overlap, are_certs_from_same_company, \
    get_certificates_different_attributes, get_certs_from_list, gen_pem_files_list, create_key_to_cert_list

"""
This program tries to analyse the certificates and gather useful data
"""


# generate list of all PEM files in directory


# Get statistics about certificates in data set.
# Recorded data:
#   duplicate public keys
#   Issuer's name & organization
#   Number of RSA & DSA keys


def main():
    DATA_DIRECTORY = 'C:/Users/drewr/Documents/Graduate_Files/Classes/ENEE657/leaf_cert/'
    # DATA_DIRECTORY = '../leaf_cert/'
    fingerprint_filename = r"./classiftable_20160716.csv"  # from https://crocs.fi.muni.cz/public/papers/usenix2016
    mask_prob_dict, groups = fingerprint.read_fingerprint_table(fingerprint_filename)
    pem_files_list = gen_pem_files_list(DATA_DIRECTORY)
    pem_certs = get_certs_from_list(pem_files_list)
    key_to_certificate_dict, num_rsa_keys, num_dsa_keys, unique_keys, duplicate_keys, num_certs_with_no_common_name, num_keys_in_each_group = create_key_to_cert_list(
        pem_certs, mask_prob_dict, groups)

    print("Total number of certificates: {0}. ".format(len(pem_certs)))
    print("Number of DSA certs = {0}".format(num_dsa_keys))
    print("Number of RSA certs = {0}. Number of unique certs: {1}. Number of duplicates: {2} ".format(
        num_rsa_keys, len(unique_keys), len(duplicate_keys)))
    print("Certificates with no common names: ", num_certs_with_no_common_name)
    print("Number of keys per group, assuming taking the most likely group per key:")
    print(num_keys_in_each_group)

    # with open('issuers.txt', 'w') as file:
    #     for key in sorted(dict_common_name, key=dict_common_name.get, reverse=True):
    #         file.write("{0}: {1}\n".format(key, dict_common_name[key]))
    #
    # with open('org.txt', 'w') as file:
    #     for key in sorted(dict_org, key=dict_org.get, reverse=True):
    #         file.write("{0}: {1}\n".format(key, dict_org[key]))

    # dumping certs_with_key to file
    # with open('certs_with_key.pickle', 'wb') as handle:
    #     pickle.dump(certs_with_key, handle, protocol=pickle.HIGHEST_PROTOCOL)

    certs_with_dup_keys = write_duplicate_keys(key_to_certificate_dict)

    print("Certs with dup keys: ", certs_with_dup_keys)
    print(groups)

    changed_subject_dict, validity_overlap_dict, num_changed_subjects, num_overlap_validity = find_certificate_changes(
        key_to_certificate_dict)

    # print out validity overlap dict & changed companies dict
    with open('validity_overlap.txt', 'w') as out_file:
        for key in validity_overlap_dict:
            for cert_a, cert_b, overlap in validity_overlap_dict[key]:
                out_file.write("{0}-{1}: {2}\n".format(cert_a.serial, cert_b.serial, overlap))

    with open('changed_subjects.txt', 'w') as out_file:
        for key in changed_subject_dict:
            for cert_a, cert_b, changes in changed_subject_dict[key]:
                try:
                    out_file.write(u"{0}-{1}: {2}\n".format(cert_a.serial, cert_b.serial, changes))
                except UnicodeEncodeError:
                    out_file.write(u"{0}-{1}: ERROR. Changes has non-valid character")

    print("Found {0} changed issuers and {1} overlapping validity instances".format(num_changed_subjects,
                                                                                    num_overlap_validity))


def find_certificate_changes(key_to_certificate_dict):
    changed_subject_dict = dict()
    validity_overlap_dict = dict()
    num_changed_subjects = 0
    num_overlap_validity = 0
    for pub_mod in key_to_certificate_dict:
        if len(key_to_certificate_dict[pub_mod]) > 1:
            current_cert_list = key_to_certificate_dict[pub_mod]
            changes_list = list()
            validity_list = list()
            for cert_a, cert_b in combinations(current_cert_list, 2):
                assert isinstance(cert_a, x509.Certificate)
                assert isinstance(cert_b, x509.Certificate)

                # check if company has changed
                if not are_certs_from_same_company(cert_a, cert_b):
                    different_attributes = get_certificates_different_attributes(cert_a, cert_b)
                    changes_list.append((cert_a, cert_b, different_attributes))
                    num_changed_subjects += 1

                # check if overlap between validity dates of certificates
                is_overlap, overlap_time = certificate_validity_overlap(cert_a, cert_b)
                if is_overlap:
                    validity_list.append((cert_a, cert_b, overlap_time))
                    num_overlap_validity += 1

            if len(changes_list) > 0:
                changed_subject_dict[pub_mod] = changes_list

            if len(validity_list) > 0:
                validity_overlap_dict[pub_mod] = validity_list
    return changed_subject_dict, validity_overlap_dict, num_changed_subjects, num_overlap_validity


def write_duplicate_keys(key_to_certificate_dict):
    certs_with_dup_keys = 0
    with open('dupes.txt', 'w') as file:
        for pub_mod in key_to_certificate_dict:
            if len(key_to_certificate_dict[pub_mod]) > 1:
                certs_with_dup_keys += len(key_to_certificate_dict[pub_mod]) - 1
                for i in range(len(key_to_certificate_dict[pub_mod])):
                    file.write(
                        key_to_certificate_dict[pub_mod][i].issuer.get_attributes_for_oid(
                            getattr(NameOID, "COMMON_NAME"))[0].value)
                    file.write(
                        key_to_certificate_dict[pub_mod][i].not_valid_after.strftime("%B %d %Y"))
                    if i < (len(key_to_certificate_dict[pub_mod]) - 1):
                        file.write(", ")
                file.write("\n")
    return certs_with_dup_keys


if __name__ == "__main__":
    main()
