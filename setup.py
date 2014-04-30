from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(
    name='pure-python-whois',
    version=version,
    description='A transliteration of the Linux whois client into pure Python.',
    long_description='',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP'
    ],
    keywords='whois, python',
    author='Christian Lerrahn',
    author_email='github@penpal4u.net',
    url='https://github.com/jsfan/pure-python-whois',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
)