import re

from collections import OrderedDict
from configparser import ConfigParser


class CAConfig:
    def __init__(self, name, **options):
        self.name = name
        self.display_name = options.get('display_name', name.capitalize())
        self.aia_name = '%s_aia' % self.name
        self.crl_ext_name = '%s_crl_ext' % self.name
        self.crl_info_name = '%s_crl_info' % self.name
        self.x509_ext_name = '%s_cert' % self.name

        if self.name == 'root':
            default_policy_name = 'root_policy'
        else:
            default_policy_name = 'default_policy'
        self.policy_name = options.get('policy_name', default_policy_name)

        self.settings = OrderedDict((
            ('certificate', '$dir/%s/ca.crt' % self.name),
            ('private_key', '$private/%s/ca.key' % self.name),
            ('new_certs_dir', '$dir/%s/archive' % self.name),
            ('serial', '$dir/%s/db/crt.srl' % self.name),
            ('database', '$dir/%s/db/index.txt' % self.name),
            ('crl', '$dir/%s/ca.crl' % self.name),
            ('crl_dir', '$dir/%s/crl' % self.name),
            ('crl_extensions', self.crl_ext_name),
            ('crlnumber', '$dir/%s/db/crl.srl' % self.name),
            ('cert_opt', 'ca_default'),
            ('copy_extensions', 'copy'),
            ('name_opt', '$name_opt'),
            ('default_bits', options.get('default_bits', '$bits')),
            ('default_days', options.get('default_days', 365)),
            ('default_crl_days', options.get('default_crl_days', 7)),
            ('default_md', options.get('default_md', '$md')),
            ('distinguished_name', 'dn'),
            ('common_name', options.get('common_name', '%s CA' % self.display_name)),
            ('org_unit', options.get('org_unit', self.display_name)),
            ('email_in_dn', 'no'),
            ('preserve', 'no'),
            ('prompt', 'no'),
            ('policy', self.policy_name),
            ('x509_extensions', self.x509_ext_name),
        ))

        self.aia = OrderedDict((
            ('caIssuers;URI.0', '$base_url/%s.crt' % self.name),
        ))

        self.crl_ext = OrderedDict((
            ('authorityKeyIdentifier', 'keyid:always'),
            ('authorityInfoAccess', '@%s' % self.aia_name),
        ))

        self.crl_info = OrderedDict((
            ('URI.0', '$base_url/%s.crl' % self.name),
        ))

        ca_type = options.get('ca_type', 'service')
        if self.name == 'root':
            self.x509_ext = OrderedDict((
                ('keyUsage', 'critical,keyCertSign,cRLSign'),
                ('basicConstraints', 'critical,CA:TRUE'),
                ('subjectKeyIdentifier', 'hash'),
                ('authorityKeyIdentifier', 'keyid:always,issuer'),
                ('nsCertType', 'sslCA'),
            ))
        elif ca_type == 'service':
            self.x509_ext = OrderedDict((
                ('keyUsage', 'critical,nonRepudiation,digitalSignature,keyEncipherment'),
                ('basicConstraints', 'critical,CA:FALSE'),
                ('subjectKeyIdentifier', 'hash'),
                ('authorityKeyIdentifier', 'keyid:always,issuer'),
                ('authorityInfoAccess', '@%s' % self.aia_name),
                ('crlDistributionPoints', '@%s' % self.crl_info_name),
                ('extendedKeyUsage', 'serverAuth,clientAuth'),
                ('nsCertType', 'server'),
            ))
        elif ca_type == 'person':
            self.x509_ext = OrderedDict((
                ('keyUsage', 'critical,nonRepudiation,digitalSignature,keyEncipherment'),
                ('basicConstraints', 'critical,CA:FALSE'),
                ('subjectKeyIdentifier', 'hash'),
                ('authorityKeyIdentifier', 'keyid:always,issuer'),
                ('authorityInfoAccess', '@%s' % self.aia_name),
                ('crlDistributionPoints', '@%s' % self.crl_info_name),
                ('extendedKeyUsage', 'emailProtection,clientAuth,anyExtendedKeyUsage'),
                ('nsCertType', 'client,email'),
            ))
        else:
            raise Exception('Do not know of certificate extension type.')


CAPolicies = OrderedDict((
    ('root_policy', OrderedDict((
        ('countryName', 'match'),
        ('localityName', 'match'),
        ('stateOrProvinceName', 'match'),
        ('organizationName', 'match'),
        ('organizationalUnitName', 'optional'),
        ('commonName', 'supplied'),
    ))),
    ('default_policy', OrderedDict((
        ('countryName', 'match'),
        ('localityName', 'match'),
        ('stateOrProvinceName', 'match'),
        ('organizationName', 'match'),
        ('organizationalUnitName', 'match'),
        ('commonName', 'supplied'),
    ))),
))


class OpenSSLConfig(ConfigParser):
    SECTCRE = re.compile(r'\[ *(?P<header>[^]]+?) *\]')

    def optionxform(self, value):
        return value
