# -*- coding: utf-8 -*-
from hachoir_core.tools import (
    humanDuration, makePrintable, humanBitRate,
    humanFrequency, humanBitSize, humanFilesize,
    normalizeNewline, makeUnicode)
from hachoir_core.i18n import _
from datetime import datetime, timedelta
from hachoir_metadata.filter import Filter, NumberFilter

MIN_PRIORITY = 100
MAX_PRIORITY = 999

MAX_STR_LENGTH = 300              # 300 characters
MAX_SAMPLE_RATE = 192000          # 192 kHz
MAX_DURATION = 366*24*60*60*1000  # 1 year
MAX_NB_CHANNEL = 8                # 8 channels
MAX_WIDTH = 200000                # 200 000 pixels
MAX_HEIGHT = MAX_WIDTH
MAX_NB_COLOR = 2 ** 24            # 16 million of color
MAX_BITS_PER_PIXEL = 256          # 256 bits/pixel
MIN_YEAR = 1900                   # Year in 1900..2030
MAX_YEAR = 2030
MAX_FRAME_RATE = 150              # 150 frame/sec
DATETIME_FILTER = Filter(datetime, datetime(MIN_YEAR, 1, 1), datetime(MAX_YEAR, 12, 31))
MAX_NB_PAGE = 20000
MAX_COMPR_RATE = 1000.0
MIN_COMPR_RATE = 0.001

NB_CHANNEL_NAME = {1: _("mono"), 2: _("stereo")}

def humanAudioChannel(value):
    return NB_CHANNEL_NAME.get(value, unicode(value))

def formatFrameRate(value):
    if isinstance(value, (int, long, float)):
        return _("%.1f fps") % value
    else:
        return value

class DataValue:
    def __init__(self, value, text):
        self.value = value
        self.text = text

class Data:
    def __init__(self, metadata, key, priority, description,  text_handler=None, type=None, filter=None):
        """
        handler is only used if value is not string nor unicode, prototype:
           def handler(value) -> str/unicode
        """
        assert MIN_PRIORITY <= priority <= MAX_PRIORITY
        assert isinstance(description, unicode)
        self.metadata = metadata
        self.key = key
        self.description = description
        self.values = []
        self.type = type
        self.text_handler = text_handler
        self.filter = filter
        self.priority = priority

    def _createItem(self, value, text=None):
        if text is None:
            if isinstance(value, unicode):
                text = value
            elif self.text_handler:
                text = self.text_handler(value)
                assert isinstance(text, unicode)
            else:
                text = makeUnicode(value)
        return DataValue(value, text)

    def add(self, value):
        if isinstance(value, tuple):
            if len(value) != 2:
                raise ValueError("Data.add() only accept tuple of 2 elements: (value,text)")
            value, text = value
        else:
            text = None

        # Skip value 'None'
        if value is None:
            return

        assert not self.type or isinstance(value, self.type)

        # Convert string to Unicode string using charset ISO-8859-1
        if isinstance(value, str):
            value = unicode(value, "ISO-8859-1")

        # Skip empty strings
        if isinstance(value, unicode):
            value = value.strip(" \t\v\n\r\0")
            if not value:
                return
            value = normalizeNewline(value)
            if MAX_STR_LENGTH < len(value):
                value = value[:MAX_STR_LENGTH] + "(...)"

        # Skip duplicates
        if value in self:
            return

        # Use filter
        if self.filter and not self.filter(value):
            self.metadata.warning("Skip value %s=%r (filter)" % (self.key, value))
            return

        # For string, if you have "verlongtext" and "verylo",
        # keep the longer value
        if isinstance(value, unicode):
            for index, item in enumerate(self.values):
                if not isinstance(item, unicode):
                    continue
                if value.startswith(item):
                    # Find longer value, replace the old one
                    self.values[index] = self._createItem(value, text)
                    return
                if item.startswith(value):
                    # Find truncated value, skip it
                    return

        # Add new value
        self.values.append(self._createItem(value, text))

    def __len__(self):
        return len(self.values)

    def __getitem__(self, index):
        return self.values[index]

    def __contains__(self, value):
        for item in self.values:
            if value == item.value:
                return True
        return False

    def __cmp__(self, other):
        return cmp(self.priority, other.priority)

def registerAllItems(meta):
    meta.register("title", 100, _("Title"))
    meta.register("author", 101, _("Author"))
    meta.register("music_composer", 102, _("Music composer"))

    meta.register("album", 200, _("Album"))
    meta.register("duration", 201, _("Duration"), # integer in milliseconde
        type=timedelta, text_handler=humanDuration, filter=NumberFilter(1, MAX_DURATION))
    meta.register("nb_page", 202, _("Nb page"), filter=NumberFilter(1, MAX_NB_PAGE))
    meta.register("music_genre", 203, _("Music genre"))
    meta.register("language", 204, _("Language"))
    meta.register("track_number", 205, _("Track number"), filter=NumberFilter(1, 99))
    meta.register("track_total", 206, _("Track total"), filter=NumberFilter(1, 99))
    meta.register("organization", 210, _("Organization"))
    meta.register("version", 220, _("Version"))


    meta.register("artist", 300, _("Artist"))
    meta.register("width", 301, _("Image width"), filter=NumberFilter(1, MAX_WIDTH))
    meta.register("height", 302, _("Image height"), filter=NumberFilter(1, MAX_HEIGHT))
    meta.register("nb_channel", 303, _("Channel"), text_handler=humanAudioChannel, filter=NumberFilter(1, MAX_NB_CHANNEL))
    meta.register("sample_rate", 304, _("Sample rate"), text_handler=humanFrequency, filter=NumberFilter(1, MAX_SAMPLE_RATE))
    meta.register("bits_per_sample", 305, _("Bits/sample"), text_handler=humanBitSize, filter=NumberFilter(1, 64))
    meta.register("image_orientation", 306, _("Image orientation"))
    meta.register("nb_colors", 307, _("Number of colors"), filter=NumberFilter(1, MAX_NB_COLOR))
    meta.register("bits_per_pixel", 308, _("Bits/pixel"), filter=NumberFilter(1, MAX_BITS_PER_PIXEL))
    meta.register("filename", 309, _("File name"))
    meta.register("file_size", 310, _("File size"), text_handler=humanFilesize)
    meta.register("pixel_format", 311, _("Pixel format"))
    meta.register("compr_size", 312, _("Compressed file size"), text_handler=humanFilesize)
    meta.register("compr_rate", 313, _("Compression rate"), filter=NumberFilter(MIN_COMPR_RATE, MAX_COMPR_RATE))

    meta.register("file_attr", 400, _("File attributes"))
    meta.register("file_type", 401, _("File type"))
    meta.register("subtitle_author", 402, _("Subtitle author"))

    meta.register("creation_date", 500, _("Creation date"),
        filter=DATETIME_FILTER)
    meta.register("last_modification", 501, _("Last modification"),
        filter=DATETIME_FILTER)
    meta.register("country", 502, _("Country"))

    meta.register("camera_aperture", 520, _("Camera aperture"))
    meta.register("camera_focal", 521, _("Camera focal"))
    meta.register("camera_exposure", 522, _("Camera exposure"))
    meta.register("camera_brightness", 530, _("Camera brightness"))
    meta.register("camera_model", 531, _("Camera model"))
    meta.register("camera_manufacturer", 532, _("Camera manufacturer"))

    meta.register("compression", 600, _("Compression"))
    meta.register("copyright", 601, _("Copyright"))
    meta.register("url", 602, _("URL"))
    meta.register("frame_rate", 603, _("Frame rate"), text_handler=formatFrameRate,
        filter=NumberFilter(1, MAX_FRAME_RATE))
    meta.register("bit_rate", 604, _("Bit rate"), text_handler=humanBitRate,
        filter=NumberFilter(1))
    meta.register("aspect_ratio", 604, _("Aspect ratio"))

    meta.register("producer", 901, _("Producer"))
    meta.register("comment", 902, _("Comment"))
    meta.register("format_version", 950, _("Format version"))
    meta.register("mime_type", 951, _("MIME type"))
    meta.register("endian", 952, _("Endian"))
