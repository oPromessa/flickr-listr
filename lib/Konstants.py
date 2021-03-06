"""
    by oPromessa, 2017
    Published on https://github.com/oPromessa/flickr-uploader/

    Helper class and functions for UPLoaDeR Global Constants.
"""

# -----------------------------------------------------------------------------
# Import section for Python 2 and 3 compatible code
# from __future__ import absolute_import, division, print_function,
#    unicode_literals
from __future__ import division    # This way: 3 / 2 == 1.5; 3 // 2 == 1

# -----------------------------------------------------------------------------
# Import section
#
import time
import lib.__version__ as __version__


# -----------------------------------------------------------------------------
# class Konstants wiht Global Constants and Variables for flickr-uploadr.
#
class Konstants:
    """ Konstants class

        >>> import lib.Konstants as KonstantsClass
        >>> Konstants = KonstantsClass.Konstants()
        >>> Konstants.media_count = 999
        >>> print(Konstants.media_count)
        999
        >>> print(0 < Konstants.Run < 10000 )
        True
    """

    # -------------------------------------------------------------------------
    # Class Global Variables
    #   class variable shared by all instances
    #
    #   TimeFormat   = Format to display date and time. Used with strftime
    #   Version      = Version Major.Minor.Fix
    #   Run          = Unique identifier for the execution Run of this process.
    #   media_count  = Counter of total files to initially upload
    #
    media_count = None
    TimeFormat = '%Y.%m.%d %H:%M:%S'
    Run = eval(time.strftime('int("%j")+int("%H")*100+int("%M")*10+int("%S")'))
    try:
        if __version__.__version__ is not None:
            Version = __version__.__version__
        else:
            Version = '2.7.0'
    except Exception:
        Version = '2.7.0'

    # -------------------------------------------------------------------------
    # Color Codes for colorful output
    Std = '\033[0m'    # white (standard/normal)
    Red = '\033[31m'   # red
    Gre = '\033[32m'   # green
    Ora = '\033[33m'   # orange
    Blu = '\033[34m'   # blue
    Pur = '\033[35m'   # purple

    # -------------------------------------------------------------------------
    # class Konstants __init__
    #
    def __init__(self):
        """ class Konstants __init__
        """
        # ---------------------------------------------------------------------
        # Instance Global Variables
        #   instance variable unique to each instance
        #
        #   base_dir      = Base configuration directory for files
        #   ini_file      = Location of INI file, normally named "uploadr.ini"
        #   etc_ini_file  = Location of INI "uploadr.ini" from ../etc folder
        #
        self.base_dir = str('.')
        self.ini_file = str('uploadr.ini')
        self.etc_ini_file = str('../etc/uploadr.ini')


# -----------------------------------------------------------------------------
# If called directly run doctests
#
if __name__ == "__main__":

    import logging

    logging.basicConfig(level=logging.DEBUG,
                        format='[%(asctime)s]:[%(processName)-11s]' +
                        '[%(levelname)-8s]:[%(name)s] %(message)s')

    import doctest
    doctest.testmod()
