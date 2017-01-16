from invoke import task


@task(
    help={
        'certificate': 'The path to the certificate file to show information.',
    }
)
def pki_show(
        ctx,
        certificate
):
    """
    Shows information about a certificate, CSR, or a CRL.
    """
    if certificate.endswith('.crt'):
        cmd = 'x509'
    elif certificate.endswith('.csr'):
        cmd = 'req'
    elif certificate.endswith('.crl') or certificate.endswith('crl.pem'):
        cmd = 'crl'
    else:
        print('Unknown certificate type.')
        return

    ctx.run('openssl %s -text -noout -in %s' % (cmd, certificate))
