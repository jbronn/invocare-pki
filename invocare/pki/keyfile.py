import os
import string

from random import SystemRandom

from invocare.openssl import openssl_genpkey
from invoke import task


@task(
    help={
        'passfile': 'The path to the password file to generate.',
        'alphabet': 'The alphabet from which password characters are chosen from.',
        'length': 'The length of the passphrase, defaults to 64.',
        'mode': 'The octal mode for the passphrase file, defaults to 0o400.',
        'seed': 'Seed for the `SystemRandom` PRNG.',
    }
)
def generate_passfile(
        ctx,
        passfile,
        alphabet=''.join([
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
            string.punctuation,
        ]),
        length=64,
        mode=0o400,
        seed=None,
):
    """
    Generates a passphrase file with a randomly generated password.
    """
    if not os.path.isfile(passfile):
        random = SystemRandom(seed)
        with open(passfile, 'w') as fh:
            for i in range(length):
                fh.write(random.choice(alphabet))
        os.chmod(passfile, mode)


@task(
    help={
        'key_file': 'The path to the private key file to generate.',
        'pass_file': 'The path to the password file to encrypt key with (optional).',
        'bits': 'The number of bits to use for the private key, defaults to 4096.',
        'cipher': 'The cipher to use for encrypting the key, defaults to "aes256".',
        'mode': 'The octal file mode for the private key, defaults to 0o400.',
    }
)
def generate_keyfile(
        ctx,
        key_file,
        pass_file=None,
        bits=4096,
        cipher='aes256',
        mode=0o400,
):
    """
    Generates an OpenSSL RSA private key.
    """
    if not os.path.isfile(key_file):
        openssl_genpkey(
            ctx,
            key_file,
            algorithm='RSA',
            cipher=pass_file and cipher,
            passwd=pass_file,
            pkeyopt={
                'rsa_keygen_bits': bits,
            }
        )
        os.chmod(key_file, mode)
