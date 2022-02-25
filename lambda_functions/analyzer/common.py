"""Common resources shared among the analyzer components."""
import logging
import os

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class FileDownloadError(Exception):
    """File can't be downloaded from S3 with a 4XX error code - do not retry."""

