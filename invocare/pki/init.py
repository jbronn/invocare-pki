import os

from invoke import task

from .profile import PKIProfile


@task(
    help={
        'profile': 'The PKI profile to initialize.',
    }
)
def pki_init(
        ctx,
        profile,
):
    """
    Initializes directory structure 
    """
    if isinstance(profile, str):
        profile = PKIProfile.from_context(profile, ctx)

    for ca_name in ('root',) + tuple(profile.intermediates.keys()):
        pki_ca_init(ctx, profile.dir, ca_name)
        ca_private = os.path.join(profile.private, ca_name)
        if not os.path.isdir(ca_private):
            os.makedirs(ca_private, 0o700)

    if not os.path.isfile(profile.config_file):
        with open(profile.config_file, 'w') as fh:
            profile.cfg.write(fh)


@task(
    help={
        'base_dir': 'The parent directory of the CA.',
        'name': 'The name of the CA to initialize.',
        'dir_mode': 'The octal file mode of the CA directories, defaults to 0o755.',
    }
)
def pki_ca_init(
        ctx,
        base_dir,
        name,
        dir_mode=0o755,
):
    """
    Initializes the directory structure for a CA in the given base directory.
    """
    ca_dir = os.path.join(base_dir, name)
    certs_dir = os.path.join(ca_dir, 'certs')
    crl_dir = os.path.join(ca_dir, 'crl')
    db_dir = os.path.join(ca_dir, 'db')
    archive_dir = os.path.join(ca_dir, 'archive')
    reqs_dir = os.path.join(ca_dir, 'reqs')

    for d in (ca_dir, certs_dir, crl_dir, db_dir, archive_dir, reqs_dir):
        if not os.path.isdir(d):
            os.makedirs(d, dir_mode)

    database = os.path.join(db_dir, 'index.txt')
    database_attr = database + '.attr'
    for f in (database, database_attr):
        if not os.path.isfile(f):
            ctx.run('cp /dev/null %s' % f)

    crlnumber = os.path.join(db_dir, 'crl.srl')
    serial = os.path.join(db_dir, 'crt.srl')
    for f in (crlnumber, serial):
        if not os.path.isfile(f):
            ctx.run('echo %s > %s' % ('01', f))

    return ca_dir
