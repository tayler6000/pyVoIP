from setuptools import find_packages
from setuptools import setup


with open("README.md", "r", encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pyVoIP',
    version='1.6.1',
    description='PyVoIP is a pure python VoIP/SIP/RTP library.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Tayler Porter',
    author_email='taylerporter@gmail.com',
    url='https://github.com/tayler6000/pyVoIP',
    project_urls={
        "Bug Tracker": "https://github.com/tayler6000/pyVoIP/issues",
        "Documentaiton": "https://pyvoip.readthedocs.io/"
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Telecommunications Industry",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Topic :: Communications :: Internet Phone",
        "Topic :: Communications :: Telephony"
    ],
    packages=find_packages(),
    package_data={'pyVoIP': ['py.typed']},
    python_requires=">=3.6"
)
