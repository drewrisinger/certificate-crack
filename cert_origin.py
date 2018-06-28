from datetime import timedelta
from itertools import combinations
from typing import List

import matplotlib.pyplot as plt
import numpy as np
from cryptography import x509
from cryptography.x509.oid import NameOID

import fingerprint
from certificate_analysis import certificate_validity_overlap, are_certs_from_same_company, \
    get_certs_from_list, gen_pem_files_list, create_key_to_cert_list, get_keys_and_duplicates

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
    # DATA_DIRECTORY = 'C:/Users/drewr/Documents/Graduate_Files/Classes/ENEE657/leaf_cert/'
    DATA_DIRECTORY = '../leaf_cert/'
    fingerprint_filename = r"./classiftable_20160716.csv"  # from https://crocs.fi.muni.cz/public/papers/usenix2016
    mask_prob_dict, groups = fingerprint.read_fingerprint_table(fingerprint_filename)
    pem_files_list = gen_pem_files_list(DATA_DIRECTORY)
    pem_certs = get_certs_from_list(pem_files_list)
    # key_to_certificate_dict, num_rsa_keys, num_dsa_keys, unique_keys, duplicate_keys, num_keys_in_each_group = create_key_to_cert_list(
    #     pem_certs, mask_prob_dict, groups)
    key_to_certificate_dict, duplicate_key_dict, num_dup_certs = get_keys_and_duplicates(
        pem_certs, mask_prob_dict, groups)
    # dict_org, num_certs_with_no_org_name = count_organization_names(pem_certs)
    # dict_common_name, num_certs_with_no_common_name = count_common_names(pem_certs)

    problem_mod_cert_dict = dict()
    for k in duplicate_key_dict:
        if len(duplicate_key_dict[k]) > 5:
            problem_mod_cert_dict[k] = duplicate_key_dict[k]

    print("Total number of certificates: {0}. ".format(len(pem_certs)))
    print("Number of DSA certs = {0}".format(num_dsa_keys))
    print("Number of RSA certs = {0}. Number of unique certs: {1}. Number of duplicates: {2} ".format(
        num_rsa_keys, len(unique_keys), len(duplicate_keys)))
    # print("Certificates with no common names: ", num_certs_with_no_common_name)
    print("Number of keys per group, assuming taking the most likely group per key:")
    print(num_keys_in_each_group)

    num_certs_with_duplicate_keys = write_duplicate_keys(key_to_certificate_dict)

    print("# of Duplicate keys: {}, Number of certificates with duplicate keys: {}".format(len(duplicate_keys), num_certs_with_duplicate_keys))
    # print(groups)

    changed_subject_dict, validity_overlap_dict, num_changed_subjects, num_overlap_validity = find_certificate_company_changes(
        key_to_certificate_dict, exclude_same_day=False)

    print("Found {0} changed issuers and {1} overlapping validity instances".format(num_changed_subjects,
                                                                                    num_overlap_validity))

    overlap_times_days = overlap_time_dict_to_timedelta_list(validity_overlap_dict)
    overlap_times = overlap_time_dict_to_timedelta_list(validity_overlap_dict, False)

    seconds_to_days = 1 / (24 * 60 * 60)
    min_overlap, max_overlap = min(overlap_times), max(overlap_times)
    overlap_std = np.std(overlap_times)
    overlap_mean = np.mean(overlap_times)
    bin_spacing = np.logspace(np.log10(min_overlap), np.log10(max_overlap), num=15)
    plt.hist(overlap_times, bins=bin_spacing)
    plt.xlabel('Time (seconds) of certificate overlap (log)')
    plt.ylabel('Number of overlapping elements')
    plt.title('Histogram of duplicate certificate validity overlap (n={})'.format(len(overlap_times)))
    plt.gca().set_xscale("log")
    plt.text(10 ** 3, 1300, r'$\mu={0:.2f}\ days,\ \sigma={1:.2f}\ days$'.format(overlap_mean * seconds_to_days,
                                                                                        overlap_std * seconds_to_days))
    plt.show()

    min_overlap_days, max_overlap_days = min(overlap_times_days), max(overlap_times_days)
    overlap_days_std = np.std(overlap_times_days)
    overlap_days_mean = np.mean(overlap_times_days)
    # bin_spacing = np.logspace(np.log10(min_overlap_days), np.log10(max_overlap_days), num=15)
    plt.hist(overlap_times_days, bins=20)
    plt.xlabel('Time (days) of certificate overlap')
    plt.ylabel('Number of overlapping elements')
    plt.title('Histogram of duplicate certificate validity overlap (n={})'.format(len(overlap_times_days)))
    plt.text(600, 1200, r'$\mu={0:.2f}\ days,\ \sigma={1:.2f}\ days$'.format(overlap_days_mean, overlap_days_std))
    plt.show()

    print("DONE")


def find_certificate_company_changes(key_to_certificate_dict, exclude_same_day=True):
    changed_subject_dict = dict()
    validity_overlap_dict = dict()
    num_changed_subjects = 0
    num_overlap_validity = 0
    num_changed_locality_only = 0
    for pub_mod in key_to_certificate_dict:
        if len(key_to_certificate_dict[pub_mod]) > 1:
            current_cert_list = key_to_certificate_dict[pub_mod]
            changes_list = list()
            validity_list = list()
            for cert_a, cert_b in combinations(current_cert_list, 2):
                assert isinstance(cert_a, x509.Certificate)
                assert isinstance(cert_b, x509.Certificate)

                # check if company has changed
                companies_are_same, difference_list = are_certs_from_same_company(cert_a, cert_b)
                if not companies_are_same:
                    changes_list.append((cert_a, cert_b, difference_list))
                    if len(difference_list) == 1 and difference_list[0][0].oid == NameOID.LOCALITY_NAME:
                        num_changed_locality_only += 1
                    num_changed_subjects += 1

                # check if overlap between validity dates of certificates
                is_overlap, overlap_time = certificate_validity_overlap(cert_a, cert_b,
                                                                        exclude_same_day=exclude_same_day)
                if is_overlap:
                    validity_list.append((cert_a, cert_b, overlap_time))
                    num_overlap_validity += 1

            if len(changes_list) > 0:
                changed_subject_dict[pub_mod] = changes_list

            if len(validity_list) > 0:
                validity_overlap_dict[pub_mod] = validity_list

    small_overlap_dict = dict()
    for key in validity_overlap_dict:
        if len(validity_overlap_dict[key]) < 50:
            small_overlap_dict[key] = validity_overlap_dict[key]

    few_certificates_overlap = overlap_time_dict_to_timedelta_list(small_overlap_dict)
    overlap_days_std = np.std(few_certificates_overlap)
    overlap_days_mean = np.mean(few_certificates_overlap)
    # bin_spacing = np.logspace(np.log10(min_overlap_days), np.log10(max_overlap_days), num=15)
    plt.hist(few_certificates_overlap, bins=20)
    plt.xlabel('Time (days) of certificate overlap')
    plt.ylabel('Number of overlapping elements')
    plt.title('Histogram of duplicate certificate validity overlap\nExcludes shared keys(n={})'.format(len(few_certificates_overlap)))
    plt.text(400, 800, r'$\mu={0:.2f}\ days,\ \sigma={1:.2f}\ days$'.format(overlap_days_mean, overlap_days_std))
    plt.show()

    # print out validity overlap dict & changed companies dict
    with open('validity_overlap.txt', 'w') as out_file:
        for key in validity_overlap_dict:
            for cert_a, cert_b, overlap in validity_overlap_dict[key]:
                out_file.write("{0}-{1}: {2}\n".format(cert_a.serial_number, cert_b.serial_number, overlap))

    with open('changed_subjects.txt', 'wb') as out_file:
        for key in changed_subject_dict:
            cert_a, _, _ = changed_subject_dict[key][0]
            out_file.write("\n{0} differences for public key {1:x}\n".format(len(changed_subject_dict[key]), key).encode('utf-8'))
            for cert_a, cert_b, changes in changed_subject_dict[key]:
                try:
                    out_file.write("{0}-{1}: ".format(cert_a.serial_number, cert_b.serial_number).encode('utf-8'))
                    for change_tuple in changes:
                        name_a, name_b = change_tuple
                        assert isinstance(name_a, x509.NameAttribute)
                        assert isinstance(name_b, x509.NameAttribute)
                        assert isinstance(name_a.oid, x509.ObjectIdentifier)
                        oid_name_str = repr(name_a.oid)
                        oid_name_str = oid_name_str[oid_name_str.find("name=") + len("name="):oid_name_str.rfind(")")]
                        out_file.write(
                            "{0}: {1} -> {2}, ".format(oid_name_str, name_a.value, name_b.value).encode('utf-8'))
                    out_file.write("\n".encode('utf-8'))
                except UnicodeEncodeError:
                    out_file.write("{0}-{1}: ERROR. Changes has non-valid character".encode('utf-8'))

    return changed_subject_dict, validity_overlap_dict, num_changed_subjects, num_overlap_validity


def write_duplicate_keys(key_to_certificate_dict):
    certs_with_dup_keys = 0
    with open('dupes.txt', 'wb') as file:
        for pub_mod in key_to_certificate_dict:
            if len(key_to_certificate_dict[pub_mod]) > 1:
                certs_with_dup_keys += len(key_to_certificate_dict[pub_mod])
                for i in range(len(key_to_certificate_dict[pub_mod])):
                    try:
                        file.write(
                            key_to_certificate_dict[pub_mod][i].issuer.get_attributes_for_oid(
                                getattr(NameOID, "COMMON_NAME"))[0].value.encode('utf-8'))
                        file.write(
                            key_to_certificate_dict[pub_mod][i].not_valid_after.strftime("%B %d %Y").encode('utf-8'))
                    except UnicodeEncodeError:
                        print("Still encountered unicode error")
                    if i < (len(key_to_certificate_dict[pub_mod]) - 1):
                        file.write(", ".encode('utf-8'))
                file.write("\n".encode('utf-8'))
    return certs_with_dup_keys


def overlap_time_dict_to_timedelta_list(valid_overlap_dict, use_days=True) -> List[timedelta]:
    overlap_timedeltas = list()
    for key in valid_overlap_dict:
        for _, _, overlap in valid_overlap_dict[key]:
            assert isinstance(overlap, timedelta)
            if use_days:
                overlap_timedeltas.append(overlap.days)
            else:
                overlap_timedeltas.append(overlap.total_seconds())

    return overlap_timedeltas


if __name__ == "__main__":
    main()
