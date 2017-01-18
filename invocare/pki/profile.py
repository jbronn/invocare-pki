import os
import sys

from collections import OrderedDict

from .config import CAConfig, CAPolicies, OpenSSLConfig


class PKIProfile:
    """
    Represents a profile for a PKI, which is backed by an OpenSSL config file.
    """

    def __init__(self, name, **options):
        self.name = name
        self.display_name = options.get('display_name', self.name.capitalize())
        self.base_dir = options.get('base_dir', os.path.curdir)
        self.dir = os.path.join(self.base_dir, self.name)
        self.config_file = os.path.join(self.dir, 'openssl.cnf')
        self.private = os.path.join(self.base_dir, 'private', self.name)

        if os.path.isfile(self.config_file):
            self.cfg = OpenSSLConfig()
            with open(self.config_file, 'r') as fh:
                self.cfg.read_file(fh)

            try:
                self.dn = self.cfg['dn']
            except KeyError:
                raise Exception('No DN section in OpenSSL config file.')

            try:
                self.defaults = self.cfg['default']
            except KeyError:
                raise Exception('No default section in OpenSSL config file.')

            try:
                self.intermediates = OrderedDict(tuple(
                    (inter_ca, OrderedDict(self.cfg[inter_ca]))
                    for inter_ca in self.defaults['intermediates'].split(',')
                ))
            except KeyError:
                raise Exception('Cannot parse intermediate certificates.')

            try:
                self.root_settings = OrderedDict(self.cfg['root'])
            except KeyError:
                raise Exception('No root section in OpenSSL config file.')
        else:
            self.root_settings = options.get('root', {})

            # By default, create one intermediate authority that can create
            # certificates for TLS services.
            self.intermediates = options.get('intermediates', {
                'tls': {
                    'display_name': 'TLS',
                    'common_name': '%s TLS CA' % self.display_name,
                },
            })

            self.defaults = OrderedDict((
                ('base_dir', self.base_dir),
                ('base_url', options.get('base_url', 'http://pki.local')),
                ('bits', options.get('bits', '4096')),
                ('display_name', self.display_name),
                ('dir', self.dir),
                ('intermediates', ','.join(sorted(self.intermediates.keys()))),
                ('md', options.get('md', 'sha256')),
                ('name_opt', options.get('name_opt', 'multiline,-esc_msb,utf8')),
                ('private', self.private),
            ))

            dn = options.get('dn', {})
            self.dn = OrderedDict((
                ('countryName', dn.get('countryName', 'US')),
                ('stateOrProvinceName', dn.get('stateOrProvinceName', 'Any-State')),
                ('localityName', dn.get('localityName', 'Springfield')),
                ('organizationName', dn.get('organizationName', 'Internet Widgits Pty Ltd')),
            ))
            if 'organizationalUnitName' in dn:
                self.dn['organizationalUnitName'] = dn['organizationalUnitName']

            self.cfg = self.default_config()

    def base_subject(self):
        """
        Returns a base OpenSSL-formatted subject field for the PKI profile.
        """
        subj = [
            'C=%s' % self.dn['countryName'],
            'ST=%s' % self.dn['stateOrProvinceName'],
            'L=%s' % self.dn['localityName'],
        ]

        if 'organizationalUnitName' in self.dn:
            subj.append('OU=%s' % self.dn['organizationalUnitName'])

        subj.append('O=%s' % self.dn['organizationName'])

        return '/' + '/'.join(subj)

    def default_config(self):
        """
        Generates default profile settings for an OpenSSL configuration file.
        """
        openssl_config = OrderedDict()

        ## Defaults
        openssl_config['default'] = self.defaults

        ## CA setting sections.
        root_settings = {
            'default_days': 1826,
            'default_crl_days': 180,
            'common_name': '%s Root CA' % self.display_name,
        }
        root_settings.update(self.root_settings)
        cas = [CAConfig('root', **root_settings)]

        for inter_ca in sorted(self.intermediates.keys()):
            ca_settings = {
                'default_days': 365,
                'default_crl_days': 7,
                'display_name': inter_ca.capitalize(),
            }
            ca_settings.update(self.intermediates[inter_ca])
            if not 'common_name' in ca_settings:
                ca_settings['common_name'] = '%s %s CA' % (
                    self.display_name, ca_settings['display_name']
                )
            cas.append(CAConfig(inter_ca, **ca_settings))

        for ca in cas:
            openssl_config[ca.name] = ca.settings

        ## Requests
        openssl_config['req'] = OrderedDict((
            ('default_bits', '$bits'),
            ('default_md', '$md'),
            ('distinguished_name', 'dn'),
            ('string_mask', 'utf8only'),
            ('utf8', 'yes'),
        ))
        openssl_config['dn'] = self.dn

        ## Policies
        openssl_config.update(CAPolicies)

        ## X509 Extensions.

        # Add special intermediate certificate extension section.
        openssl_config['intermediate_cert'] = OrderedDict((
            ('keyUsage', 'critical,keyCertSign,cRLSign'),
            ('basicConstraints', 'critical,CA:TRUE,pathlen:0'),
            ('subjectKeyIdentifier', 'hash'),
            ('authorityKeyIdentifier', 'keyid:always,issuer:always'),
            ('authorityInfoAccess', '@%s' % cas[0].aia_name),
            ('crlDistributionPoints', '@%s' % cas[0].crl_info_name),
            ('nsCertType', 'sslCA'),
        ))

        for ca in cas:
            openssl_config[ca.x509_ext_name] = ca.x509_ext

        ## CRL Extensions
        for ca in cas:
            openssl_config[ca.crl_ext_name] = ca.crl_ext
            openssl_config[ca.crl_info_name] = ca.crl_info
            openssl_config[ca.aia_name] = ca.aia

        cfg = OpenSSLConfig()
        cfg.read_dict(openssl_config)
        return cfg

    @classmethod
    def from_context(cls, obj, ctx):
        if isinstance(obj, PKIProfile):
            return obj
        else:
            config = ctx.config.get('pki', {})
            profile_name = obj or config.get('profile', None)
            if profile_name:
                options = config.get(profile_name, {})
                return PKIProfile(profile_name, **options)
            else:
                sys.stderr.write('Must provide a profile name.\n')
                sys.exit(os.EX_USAGE)


    def req_cfg(self, ca_name, common_name, san=None):
        """
        Returns an ordered dictionary representing an OpenSSL configuration file
        for a certificate request.
        """
        req_cfg = OrderedDict((
            ('req', OrderedDict((
                ('distinguished_name', 'dn'),
            ('prompt', 'no'),
            ))),
            ('dn', OrderedDict(self.cfg['dn'])),
        ))

        # Add in the common name and OU for the CA.
        req_cfg['dn'].update({
            'commonName': common_name,
            'organizationalUnitName': self.cfg[ca_name]['org_unit'],
        })

        # Add on extensions for supporting subjectAltName.
        if san:
            if isinstance(san, str):
                san = san.split(',')
            req_cfg['req']['req_extensions'] = 'req_ext'
            req_cfg['req_ext'] = OrderedDict([('subjectAltName', '@san')])

            # TODO: Support different types of SAN entries.
            req_cfg['san'] = OrderedDict([
                ('DNS.%d' % i, alt_name)
                for i, alt_name in enumerate(san, 1)
            ])

        cfg = OpenSSLConfig()
        cfg.read_dict(req_cfg)
        return cfg
