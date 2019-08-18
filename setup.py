import os
import platform
import subprocess
import sys
from pprint import pprint
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

c_module_name = '_tpm20'


class CMakeExtension(Extension):
    def __init__(self, name, cmake_lists_dir='.', sources=[], **kwa):
        Extension.__init__(self, name, sources=sources, **kwa)
        self.cmake_lists_dir = os.path.abspath(cmake_lists_dir)


class CMakeBuild(build_ext):

    def build_extensions(self):
        try:
            subprocess.check_output(['cmake', '--version'])
        except OSError:
            raise RuntimeError('Cannot find CMake executable')

        for ext in self.extensions:

            extdir = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))
            cfg = 'Debug'
            cmake_args = [
                '-DCMAKE_BUILD_TYPE=%s' % cfg,
                '-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{}={}'.format(cfg.upper(), extdir),
                '-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_{}={}'.format(cfg.upper(), self.build_temp),
                '-DPYTHON_EXECUTABLE={}'.format(sys.executable),
            ]

            if platform.system() == 'Windows':
                raise RuntimeError('Windows platform is not supported')

            pprint(cmake_args)

            if not os.path.exists(self.build_temp):
                os.makedirs(self.build_temp)

            # Config and build the extension
            subprocess.check_call(['cmake', ext.cmake_lists_dir] + cmake_args,
                                  cwd=self.build_temp)
            subprocess.check_call(['cmake', '--build', '.', '--config', cfg],
                                  cwd=self.build_temp)


# The following line is parsed by Sphinx
version = '0.1.0'

setup(name='tpm20',
      packages=['tpm20'],
      version=version,
      build_base='.build',
      description='Simple TPM20 binding',
      author='Nikita Kuznetsov',
      author_email='me@daedalus.ru',
      url='https://github.com/kalloc/pytpm20',
      keywords=['TPM20', 'TSS', 'trusted platform module', 'binding'],
      ext_modules=[CMakeExtension(c_module_name)],
      cmdclass={'build_ext': CMakeBuild},
      install_requires=['ecdsa>=0.13'],
      python_requires=">=3.7",
      zip_safe=False,
      classifiers=[
          "Programming Language :: Python :: 3",
          "Operating System :: POSIX :: Linux",
      ],
      )

