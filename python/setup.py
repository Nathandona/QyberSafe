from pybind11.setup_helpers import Pybind11Extension, build_ext
from pybind11 import get_cmake_dir
import pybind11
import sys
import os
from setuptools import setup, Extension

# Define the extension module
ext_modules = [
    Pybind11Extension(
        "qybersafe._core",
        [
            "src/bindings.cpp",
            # Add your C++ source files here
        ],
        include_dirs=[
            pybind11.get_include(),
            "../src/include",
            "../src/src",
        ],
        libraries=[],
        cxx_std=17,
        define_macros=[("VERSION_INFO", '"dev"')],
    ),
]

setup(
    name="qybersafe",
    version="0.1.0",
    author="QyberSafe Team",
    author_email="info@qybersafe.io",
    description="Modern post-quantum cryptography library",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/qybersafe/qybersafe",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    packages=["qybersafe"],
    python_requires=">=3.7",
    install_requires=[
        "pybind11>=2.6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov",
            "black",
            "flake8",
            "mypy",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: C++",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    zip_safe=False,
)