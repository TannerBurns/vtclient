import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
     name='VTClient',  
     version='2.0.2',
     author="Tanner Burns",
     author_email="tjburns102@gmail.com",
     description="An asynchronous client for VirusTotal",
     long_description=long_description,
     long_description_content_type="text/markdown",
     url="https://github.com/tannerburns/vtclient",
     packages=setuptools.find_packages(),
     include_package_data=True,
     install_requires=[
         "aiorequests @ https://github.com/TannerBurns/aiorequests/archive/master.zip"
     ],
     classifiers=[
         "Programming Language :: Python :: 3",
         "Operating System :: OS Independent",
     ],
 )