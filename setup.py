from setuptools import setup


_locals = {}
with open('invocare/pki/_version.py') as fh:
    exec(fh.read(), None, _locals)
version = _locals['__version__']


setup(name='invocare-pki',
      version=version,
      author='Justin Bronn',
      author_email='jbronn@gmail.com',
      description='Public Key Infrastructure Invocations',
      long_description='Invoke tasks for managing an OpenSSL-based PKI.',
      license='Apache License 2.0',
      url='https://github.com/jbronn/invocare-pki',
      download_url='https://pypi.python.org/pypi/invocare-pki/',
      install_requires=[
        'invocare-openssl>=0.0.1,<1.0.0',
      ],
      packages=['invocare.pki'],
      zip_safe=False,
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
      ],
)
