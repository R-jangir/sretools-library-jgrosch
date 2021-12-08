import logging


# ----------------------------------------------------------
#
# add_log_level_argument
#
# ----------------------------------------------------------
def add_log_level_argument(parser: argparse.parser) -> None:
    """
    Args:

    Returns:
    
    """
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity, default is WARNING",
                        action="count", default=0)
    return
    #


# ----------------------------------------------------------
#
# set_log_level
#
# ----------------------------------------------------------
def set_log_level(verbose: int) -> None:
    """
    Args:

    Returns:
    
    """
    if verbose == 1:
        logging.basicConfig(level=logging.INFO)
    elif verbose >= 2:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    return
    #
