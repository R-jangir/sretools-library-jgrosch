import logging


def add_log_level_argument(parser):
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity, default is WARNING",
                        action="count", default=0)


def set_log_level(verbose):
    if verbose == 1:
        logging.basicConfig(level=logging.INFO)
    elif verbose >= 2:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)
