import pathlib
from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent

VERSION      = '0.5.0'
PACKAGE_NAME = 'sretools'
AUTHOR       = 'Josef Grosch'
AUTHOR_EMAIL = 'josef.grosch@addepar.com'
URL          = 'https://github.com/josefgrosch/sretools-library'

LICENSE = 'Copyright (c) 2021 Addepar, Inc.'
DESCRIPTION = 'Library of the Arcade tools'
LONG_DESCRIPTION = (HERE / "README.md").read_text()
LONG_DESC_TYPE = "text/markdown"

INSTALL_REQUIRES = [
    'numpy',
    'pandas'
]

setup(name=PACKAGE_NAME,
      version=VERSION,
      description=DESCRIPTION,
      long_description=LONG_DESCRIPTION,
      long_description_content_type=LONG_DESC_TYPE,
      author=AUTHOR,
      license=LICENSE,
      author_email=AUTHOR_EMAIL,
      url=URL,
      install_requires=INSTALL_REQUIRES,
      packages=find_packages()
      )
