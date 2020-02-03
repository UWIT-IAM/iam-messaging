# from distutils.core import setup
from setuptools import setup, find_packages
setup(name='messagetools',
      version='2.0',
      description='UW-IT messaging library',
      packages=find_packages(),
      include_package_data=True,
     )
