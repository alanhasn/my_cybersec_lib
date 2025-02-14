from setuptools import setup, find_packages

setup(
    name="Security",
    version="1.0",
    author="Whoami",
    author_email="whoamialan11@gmail.com",
    description="A simple cybersecurity scanning library for scan the individual target and Networks easily...",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/alanhasn/my_cybersec_lib",
    packages=find_packages(),
    install_requires=["python-nmap"], 
        classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
