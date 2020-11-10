try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

package_name = 'tcpsession'
description = ('Native Python library that extracts out session data sent over a TCP connection'
              ' from both sides from a pcap')
readme = open('README.md').read()
long_description = readme
package = __import__(package_name)
print(package)
package_version = package.__version__
author = "@NULL_by_0"

setup(name=package_name,
      version=package_version,
      author=author,
      description=description,
      long_description=long_description,
      packages=['tcpsession'],
      install_requires=['dpkt'],
      license='MIT')

