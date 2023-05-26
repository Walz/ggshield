from pathlib import Path
from ggshield.scan import Files, StringScannable
    file1 = StringScannable(content="", url="file1")
    file2 = StringScannable(content="", url="file2")
def test_string_scannable_path():
    GIVEN a StringScannable instance
    WHEN path() is called
    THEN it returns the right value
    scannable = StringScannable(url="custom:/some/path", content="")
    assert scannable.path == Path("/some/path")