import os
import time
from datetime import timedelta
from typing import Tuple, List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import NameOID
from fuzzywuzzy import fuzz

import fingerprint


def certificate_validity_overlap(certificate_a: x509.Certificate, certificate_b: x509.Certificate) -> \
        Tuple[bool, timedelta]:
    """
    Checks if the validity periods of two x509 certificates overlaps
    :param certificate_a: x509 certificate to compare
    :param certificate_b: second x509 certificate to compare
    :return: True if the validity intervals for the certificates overlap, False otherwise
    """
    cert_a_start_time, cert_a_end_time = certificate_a.not_valid_before.date(), certificate_a.not_valid_after.date()
    cert_b_start_time, cert_b_end_time = certificate_b.not_valid_before.date(), certificate_b.not_valid_after.date()

    # check if b's start time falls in a's interval
    if cert_a_start_time < cert_b_start_time < cert_a_end_time:
        return True, certificate_a.not_valid_after - certificate_b.not_valid_before
    elif cert_a_start_time < cert_b_end_time < cert_a_end_time:
        return True, certificate_b.not_valid_after - certificate_a.not_valid_before
    else:
        return False, timedelta(0)


def are_certs_from_same_company(certificate_a: x509.Certificate, certificate_b: x509.Certificate) \
        -> Tuple[bool, List[x509.NameAttribute]]:
    """
    Compares companies certs are assigned to see if they are the same. Checks all attributes.
    :param certificate_a: an x509 certificate
    :param certificate_b: a second x509 certificate
    :return: boolean
    """
    assert isinstance(certificate_b, x509.Certificate)
    assert isinstance(certificate_a, x509.Certificate)

    subject_a_rdns_list = certificate_a.subject.rdns
    subject_b_rdns_list = certificate_b.subject.rdns

    return _is_rdns_match(subject_a_rdns_list, subject_b_rdns_list)


def are_certs_from_same_issuer(certificate_a: x509.Certificate, certificate_b: x509.Certificate) \
        -> Tuple[bool, List[x509.NameAttribute]]:
    """
    Compares certificate issuers to see if they are the same. Checks all attributes.
    :param certificate_a: an x509 certificate
    :param certificate_b: a second x509 certificate
    :return: boolean
    """
    assert isinstance(certificate_a, x509.Certificate)
    assert isinstance(certificate_b, x509.Certificate)

    issuer_a_rdns_list = certificate_a.issuer.rdns
    issuer_b_rdns_list = certificate_b.issuer.rdns

    return _is_rdns_match(issuer_a_rdns_list, issuer_b_rdns_list)


def _is_rdns_match(rdns_list_a: List[x509.RelativeDistinguishedName], rdns_list_b: List[x509.RelativeDistinguishedName]) \
        -> Tuple[bool, List[x509.NameAttribute]]:
    """
    Performs fuzzy search to check if two RDNS records are the same. Only checks if the record type exists in both
    :param rdns_list_a:
    :param rdns_list_b:
    :return:
    """
    retval = True  # default to assuming same
    diff_list = list()
    for rdns_a in rdns_list_a:
        for name_attr_a in rdns_a:
            for rdns_b in rdns_list_b:
                for name_attr_b in rdns_b:
                    assert isinstance(name_attr_a, x509.NameAttribute)
                    assert isinstance(name_attr_b, x509.NameAttribute)
                    # if OID matches, compare their values
                    if name_attr_a.oid == name_attr_b.oid and name_attr_a.value != name_attr_b.value:
                        # does fuzzy search to check if there is < 80% match b/w values
                        if fuzz.token_sort_ratio(name_attr_a.value, name_attr_b.value) < 80:
                            retval = False
                            diff_list.append((name_attr_a, name_attr_b))
    return retval, diff_list


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


def attribute_count(common_names: dict, cert: x509.Certificate, attribute: str) -> None:
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


def gen_pem_files_list(data_directory):
    pem_files_list = list()
    for file in os.listdir(data_directory):
        if file.endswith(".pem"):
            pem_files_list.append(data_directory + file)

    print("Num of PEM files: " + str(len(pem_files_list)))
    return pem_files_list


def create_key_to_cert_list(pem_certs, mask_prob_dict, groups):
    num_rsa_keys = 0
    num_dsa_keys = 0
    num_keys_in_each_group = [0] * len(groups)
    seen_keys = set()
    duplicate_keys = []
    unique_keys = []
    # dict_common_name = dict()
    # dict_org = dict()
    num_certs_with_no_common_name = 0
    # num_certs_with_no_org_name = 0
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
            num_keys_in_each_group[
                groups.index(fingerprint.get_likely_group_from_key(pub_mod, mask_prob_dict, groups))] += 1
            # if fingerprint.classify_key(pub_mod, mask_prob_dict, groups)[3] == 100:
            # print(pub_key.public_bytes(
            #     encoding=serialization.Encoding.PEM,
            #     format=serialization.PublicFormat.SubjectPublicKeyInfo
            # ))
        else:
            raise ValueError
    return key_to_certificate_dict, num_rsa_keys, num_dsa_keys, unique_keys, duplicate_keys, \
           num_certs_with_no_common_name, num_keys_in_each_group
