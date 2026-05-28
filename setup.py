from setuptools import find_packages, setup


setup(
    name="detecode",
    version="0.1.0",
    description="CLI AI-assisted vulnerability scanner for PHP and JavaScript source code.",
    packages=find_packages(),
    include_package_data=True,
    package_data={"detecode": ["rules/*.yaml"]},
    install_requires=["rich>=13.0.0"],
    extras_require={
        "ai": ["transformers>=4.35.0", "torch>=2.0.0"],
        "semgrep": ["semgrep>=1.50.0"],
        "train": ["datasets>=2.18.0", "scikit-learn>=1.3.0"],
        "dev": ["pytest>=7.4.0"],
    },
    entry_points={"console_scripts": ["detecode=detecode.cli:main"]},
    python_requires=">=3.9",
)
