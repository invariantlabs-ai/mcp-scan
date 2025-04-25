# Inspired from the following SO answer
# https://stackoverflow.com/questions/24277488/in-python-how-to-capture-the-stdout-from-a-c-shared-library-to-a-variable/57677370#57677370
import io
import os
import sys
import tempfile
from types import TracebackType


class SuppressStd(object):
    """Context to capture stderr and stdout at C-level."""

    def __init__(self) -> None:
        std_out = sys.__stdout__
        std_err = sys.__stderr__
        if std_out is None or std_err is None:
            raise RuntimeError("stdout or stderr is None")
        self.orig_stdout_fileno = std_out.fileno()
        self.orig_stderr_fileno = std_err.fileno()
        self.output: None | str = None

    def __enter__(self) -> "SuppressStd":
        # Redirect the stdout/stderr fd to temp file
        self.orig_stdout_dup = os.dup(self.orig_stdout_fileno)
        self.orig_stderr_dup = os.dup(self.orig_stderr_fileno)
        self.tfile = tempfile.TemporaryFile(mode="w+b")
        os.dup2(self.tfile.fileno(), self.orig_stdout_fileno)
        os.dup2(self.tfile.fileno(), self.orig_stderr_fileno)

        # Store the stdout object and replace it by the temp file.
        self.stdout_obj = sys.stdout
        self.stderr_obj = sys.stderr
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

        return self

    def __exit__(
        self,
        exc_class: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        # Make sure to flush stdout
        print(flush=True)

        # Restore the stdout/stderr object.
        sys.stdout = self.stdout_obj
        sys.stderr = self.stderr_obj

        # Close capture file handle
        os.close(self.orig_stdout_fileno)
        os.close(self.orig_stderr_fileno)

        # Restore original stderr and stdout
        os.dup2(self.orig_stdout_dup, self.orig_stdout_fileno)
        os.dup2(self.orig_stderr_dup, self.orig_stderr_fileno)

        # Close duplicate file handle.
        os.close(self.orig_stdout_dup)
        os.close(self.orig_stderr_dup)

        # Copy contents of temporary file to the given stream
        self.tfile.flush()
        self.tfile.seek(0, io.SEEK_SET)
        self.output = self.tfile.read().decode()
        self.tfile.close()
