import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
     name='VtClient',  
     version='1.0',
     scripts=['VtClient.py'] ,
     author="Tanner Burns",
     author_email="tjburns102@gmail.com",
     description="An asynchronous client for VirusTotal",
     long_description=long_description,
     long_description_content_type="text/markdown",
     url="https://github.com/tannerburns/vtclient",
     packages=setuptools.find_packages(),
     classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: MIT License",
         "Operating System :: OS Independent",
     ],
 )