from setuptools import setup, find_packages

setup(
    name="SecureTool",
    version="2.1.0",
    author="WhoamiAlan",
    author_email="whoamialan11@gmail.com",
    description="Comprehensive cybersecurity tools including network scanning, password strength checking, web scraping, encryption, and validation.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/alanhasn/my_cybersec_lib",
    packages=find_packages(),
    install_requires=[
        "python-nmap>=0.7.1",
        "requests>=2.32.3",
        "beautifulsoup4>=4.12.0",
        "cryptography>=41.0.0"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
        "Topic :: Internet :: WWW/HTTP :: Indexing/Search",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires='>=3.6',
    keywords="security cybersecurity scanning password encryption validation scraping",
)
