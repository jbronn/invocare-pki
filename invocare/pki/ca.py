import os
import sys

from collections import OrderedDict

from invocare.openssl import openssl_ca, openssl_req
from invoke import task

from .config import OpenSSLConfig
from .keyfile import generate_keyfile, generate_passfile
from .profile import PKIProfile


@task(
    help={
        'profile': 'The profile to create the intermediate CA under.',
        'ca_name': 'The name of the CA to create.',
        'days': 'The number of days the CA certificate is valid for.',
    }
)
def inter_ca(ctx, profile, ca_name, bits=None, days=None):
    """
    Initializes an intermediate CA in the profile.
    """
    if isinstance(profile, str):
        profile = PKIProfile.from_context(profile, ctx)

    if not ca_name in profile.intermediates:
        sys.stderr.write('No configuration for "%s" intermediate CA.\n' % ca_name)
        sys.exit(os.EX_CONFIG)

    if not os.path.isfile(profile.config_file):
        sys.stderr.write('PKI profile "%s" has not been initialized.\n' % profile.name)
        sys.exit(os.EX_CONFIG)

    if not os.path.isfile(os.path.join(profile.dir, 'root', 'ca.crt')):
        sys.stderr.write('Root CA for PKI profile "%s" does not exist.\n' % profile.name)
        sys.exit(os.EX_CONFIG)

    ca_dir = os.path.join(profile.dir, ca_name)
    cert_file = os.path.join(ca_dir, 'ca.crt')
    crl_file = os.path.join(ca_dir, 'ca.crl')
    ca_bundle = os.path.join(ca_dir, 'ca-bundle.crt')
    req_dir = os.path.join(profile.dir, 'root', 'reqs')
    req_file = os.path.join(req_dir, ca_name + '.csr')
    key_file = os.path.join(profile.private, ca_name, 'ca.key')
    pass_file = os.path.join(profile.private, ca_name, 'ca.pass')

    if not os.path.isfile(key_file):
        if not bits:
            # Use CA's bit setting, or the policy default.
            bits = profile.cfg[ca_name]['default_bits']
            if bits.startswith('$'):
                bits = profile.cfg['default']['bits']
        generate_passfile(ctx, pass_file)
        generate_keyfile(ctx, key_file, pass_file, bits=int(bits))

    if not os.path.isfile(req_file):
        ca_subject = '/'.join([
            profile.base_subject(),
            'OU=%s' % profile.cfg[ca_name]['org_unit'],
            'CN=%s' % profile.cfg[ca_name]['common_name'],
        ])

        openssl_req(
            ctx,
            key_file,
            req_file,
            config_file=profile.config_file,
            extensions='intermediate_cert',
            passin=pass_file,
            subj=ca_subject
        )

    if not os.path.isfile(cert_file):
        # Sign intermediate with the Root CA settings.
        root_pass = os.path.join(profile.private, 'root', 'ca.pass')

        openssl_ca(
            ctx,
            'sign',
            config_file=profile.config_file,
            config_name='root',
            days=days or int(profile.cfg['root']['default_days']),
            extensions='intermediate_cert',
            in_file=req_file,
            out_file=cert_file,
            passin=root_pass,
        )

        if os.stat(cert_file).st_size:
            os.chmod(cert_file, 0o444)
            root_cert_file = os.path.join(
                profile.dir, 'root', 'certs', '%s.crt' % ca_name
            )
            if not os.path.isfile(root_cert_file):
                ctx.run('cp -p %s %s' % (cert_file, root_cert_file))
        else:
            # Clean up if not signed.
            os.unlink(cert_file)
            return

        # Generate a bundle that includes the Root CA.
        if not os.path.isfile(ca_bundle):
            ctx.run(
                'cat %s %s > %s' % (
                    cert_file,
                    os.path.join(profile.dir, 'root', 'ca.crt'),
                    ca_bundle
                )
            )
            os.chmod(ca_bundle, 0o444)

        # Generate the initial CRL.
        if not os.path.isfile(crl_file):
            openssl_ca(
                ctx,
                'gencrl',
                config_file=profile.config_file,
                config_name=ca_name,
                passin=pass_file,
                out_file=crl_file,
            )
    else:
        sys.stderr.write('Intermediate CA certificate already exists for "%s".\n' % ca_name)


@task
def root_ca(ctx, profile, bits=None, days=3652):
    """
    Initializes the root CA for the profile.
    """
    if isinstance(profile, str):
        profile = PKIProfile.from_context(profile, ctx)

    if not os.path.isfile(profile.config_file):
        sys.stderr.write('PKI profile "%s" has not been initialized.\n' % profile.name)
        sys.exit(os.EX_CONFIG)

    ca_dir = os.path.join(profile.dir, 'root')
    cert_file = os.path.join(ca_dir, 'ca.crt')
    crl_file = os.path.join(ca_dir, 'ca.crl')
    key_file = os.path.join(profile.private, 'root', 'ca.key')
    pass_file = os.path.join(profile.private, 'root', 'ca.pass')
    req_file = os.path.join(ca_dir, 'reqs', 'root.csr')

    # Generate the private key and password file for the root CA.
    if not os.path.isfile(key_file):
        if not bits:
            # Use CA's bit setting, or the policy default.
            bits = profile.cfg['root']['default_bits']
            if bits.startswith('$'):
                bits = profile.cfg['default']['bits']
        generate_passfile(ctx, pass_file)
        generate_keyfile(ctx, key_file, pass_file, bits=int(bits))

    # Generate CSR for the Root CA.
    if not os.path.isfile(req_file):
        root_subject = '/'.join([
            profile.base_subject(),
            'CN=%s' % profile.cfg['root']['common_name']
        ])

        openssl_req(
            ctx,
            key_file,
            req_file,
            config_file=profile.config_file,
            extensions=profile.cfg['root']['x509_extensions'],
            passin=pass_file,
            subj=root_subject,
        )
        os.chmod(req_file, 0o444)

    # Self-sign the Root CA.
    if not os.path.isfile(cert_file):
        openssl_ca(
            ctx,
            'selfsign',
            config_file=profile.config_file,
            config_name='root',
            days=days,
            in_file=req_file,
            out_file=cert_file,
            passin=pass_file,
        )

        # Clean up if not signed.
        if not os.stat(cert_file).st_size:
            os.unlink(cert_file)
            return

        # Generate the initial CRL.
        if not os.path.isfile(crl_file):
            openssl_ca(
                ctx,
                'gencrl',
                config_file=profile.config_file,
                config_name='root',
                passin=pass_file,
                out_file=crl_file,
            )
    else:
        sys.stderr.write('Root CA certificate already exists %s profile.\n' % profile)
        sys.exit(os.EX_USAGE)


@task
def pki_cert(
        ctx,
        profile,
        ca_name,
        common_name,
        days=None,
        bits=None,
        san=None,
):
    if isinstance(profile, str):
        profile = PKIProfile.from_context(profile, ctx)

    # TODO: Sanitize for things like wildcard certs.
    cert_name = common_name

    ca_dir = os.path.join(profile.dir, ca_name)
    cert_file = os.path.join(ca_dir, 'certs', '%s.crt' % cert_name)
    req_conf = os.path.join(ca_dir, 'reqs', '%s.cnf' % cert_name)
    req_file = os.path.join(ca_dir, 'reqs', '%s.csr' % cert_name)
    key_file = os.path.join(profile.private, ca_name, '%s.key' % cert_name)
    pass_file = os.path.join(profile.private, ca_name, 'ca.pass')

    # Generate unencrypted private key.
    if not os.path.isfile(key_file):
        if not bits:
            # Use CA's bit setting, or the policy default.
            bits = profile.cfg[ca_name]['default_bits']
            if bits.startswith('$'):
                bits = profile.cfg['default']['bits']
        generate_keyfile(ctx, key_file, bits=int(bits))

    if not os.path.isfile(req_file):
        # Generate config file for CSR request.
        with open(req_conf, 'w') as fh:
            profile.req_cfg(ca_name, common_name, san).write(fh)

        # Generate the CSR.
        openssl_req(
            ctx,
            key_file,
            req_file,
            config_file=req_conf,
        )

    if not os.path.isfile(cert_file):
        openssl_ca(
            ctx,
            'sign',
            config_file=profile.config_file,
            config_name=ca_name,
            days=days or int(profile.cfg[ca_name]['default_days']),
            extensions=profile.cfg[ca_name]['x509_extensions'],
            in_file=req_file,
            out_file=cert_file,
            passin=pass_file,
        )

        if os.stat(cert_file).st_size:
            os.chmod(cert_file, 0o444)
        else:
            # Clean up if not signed.
            os.unlink(cert_file)
            return


@task
def pki_revoke(
        ctx,
        profile,
        ca_name,
        cert_file,
        reason='unspecified',
):
    if isinstance(profile, str):
        profile = PKIProfile.from_context(profile, ctx)

    crl_file = os.path.join(profile.dir, ca_name, 'ca.crl')
    pass_file = os.path.join(profile.private, ca_name, 'ca.pass')

    openssl_ca(
        ctx,
        'revoke',
        config_file=profile.config_file,
        config_name=ca_name,
        in_file=cert_file,
        passin=pass_file,
    )

    openssl_ca(
        ctx,
        'gencrl',
        config_file=profile.config_file,
        config_name=ca_name,
        passin=pass_file,
        out_file=crl_file,
    )
