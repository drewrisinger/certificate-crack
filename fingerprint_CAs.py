from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.oid import NameOID

import fingerprint
from certificate_analysis import get_certs_from_list, gen_pem_files_list


def create_issuer_to_cert_list(pem_certs, mask_prob_dict, groups):
    common_name_to_modulus = dict()
    for certificate in pem_certs:
        pub_key = certificate.public_key()
        common_name = ""
        # retrieve common name(issuer) for certs
        if isinstance(pub_key, RSAPublicKey):
            pub_mod = pub_key.public_numbers().n
            if certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME):
                common_name = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            common_name = common_name.split(" ")[0].lower()
            # print (common_name)
            if common_name in common_name_to_modulus:
                common_name_to_modulus[common_name].append(pub_mod)
            else:
                common_name_to_modulus[common_name] = [pub_mod]
    return common_name_to_modulus


DATA_DIRECTORY = '/home/slashzero/Downloads/leaf_cert/'
fingerprint_filename = r"./classiftable_20160716.csv"  # from https://crocs.fi.muni.cz/public/papers/usenix2016
mask_prob_dict, groups = fingerprint.read_fingerprint_table(fingerprint_filename)
pem_files_list = gen_pem_files_list(DATA_DIRECTORY)
pem_certs = get_certs_from_list(pem_files_list)

# dictionary of CAs and their associated modulus
common_name_to_modulus = create_issuer_to_cert_list(pem_certs, mask_prob_dict, groups)

for CA in common_name_to_modulus:
    norm_prob, group = fingerprint.classify_key_list(common_name_to_modulus[CA], mask_prob_dict, groups)
    print(str(max(norm_prob)) + ", " + str(group))
