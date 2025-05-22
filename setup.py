from setuptools import setup, find_packages

setup(
    name="SecureTool",
    version="2.0.0",  # نسخة جديدة بصيغة معيارية (semver)
    author="WhoamiAlan",
    author_email="whoamialan11@gmail.com",
    description="Comprehensive cybersecurity tools including network scanning, password strength checking, and web scraping.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/alanhasn/my_cybersec_lib",
    packages=find_packages(),
    install_requires=["python-nmap"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
    ],
    python_requires='>=3.6',
)
