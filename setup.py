import os
from setuptools import setup

def readme():
    with open('README.rst') as f:
        return f.read()

def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            if filename.endswith("~"):
                continue
            paths.append(os.path.join(path, filename))
    print( paths )
    return paths


setup(name='kbr_api',
      version='0.0.1',
      description='python api framework',
      url='https://github.com/brugger/kbr-api-app/',
      author='Kim Brugger',
      author_email='kbr@brugger.dk',
      license='MIT',
      packages=['kbr_api'],
      install_requires=[
          'python-oauth2',
          'tornado',
          'tabulate',
          'records'
      ],
      classifiers=[
          'Development Status :: 0.0.1',
          'License :: MIT License',
          'Programming Language :: Python :: 3'
      ],
      scripts=[ 'bin/api_cli.py',
                'bin/api.py',
               ],
      data_files=[('share/kbr-api/sql/', package_files('sql/')),
                  ('share/kbr-api/templates', package_files('templates/')),
                  ('share/kbr-api/', ['api.json'])],

      include_package_data=True,
      zip_safe=False)
