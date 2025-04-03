from setuptools import setup, find_packages

setup(
    name='py_nessus_pro',
    version='1.3.3',
    packages=find_packages(),
    install_requires=[
         'selenium',
         'beautifulsoup4',
         'python-slugify',
         'requests',
         'loguru',
         'typer',
         'typing',
    ],
    entry_points={
        'console_scripts': [
            'py-nessus-pro=py_nessus_pro.py_nessus_pro_cli:app',
        ],
    },
    author='Matbe34',
    description='Python library for managing Nessus Professional.',
    url='https://github.com/Matbe34/py-nessus-pro',
    classifiers=['Programming Language :: Python :: 3'],
    long_description="""PyNessusPro
===========
    
``py_nessus_pro`` is a Python module that provides a high-level interface for interacting with a Nessus vulnerability scanner. The module uses the Nessus REST API to perform various operations, such as creating and managing scans, retrieving scan metadata and reports, and searching for scans by name or date. It provides Nessus Professional with an interface to expand the read-omly API and be able to launch scans and modify them.

Installation
------------

To install ``py_nessus_pro``\, simply run:

.. code:: 

   pip install py-nessus-pro

Usage
------------

Create an instance

.. code:: python

   from py_nessus_pro import PyNessusPro

   nessus_server = "https://nessus-server-url:8834"
   username = "admin"
   password = "password"
   nessus = PyNessus(nessus_server, username, password)

Launch a scan:

.. code:: python

   scan_name = "My Scan"
   scan_target = "127.0.0.1"
   scan_folder = "Automatic Scan Test"

   scan_index = nessus.new_scan(name=scan_name, target=scan_target, folder=scan_folder)

License
-------

``py_nessus_pro`` is licensed under the GNU GENERAL PUBLIC LICENSE
Version 2. See the ``LICENSE`` file for more information.

.. |Upload Python Package| image:: https://github.com/Matbe34/py-nessus/actions/workflows/pynessus-publish.yml/badge.svg?event=release
   :target: https://github.com/Matbe34/py-nessus-pro/actions/workflows/pynessus-publish.yml
"""
)
