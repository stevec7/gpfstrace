try:
    from setuputils import setup
except:
    from distutils.core import setup


    
setup(
    name = 'gpfstrace',
    version = '0.0.1',
    description = 'libraries for analyzing GPFS trace logs',
    author = 'stevec7',
    author_email = 'none',
    packages = ['gpfstrace']






)
