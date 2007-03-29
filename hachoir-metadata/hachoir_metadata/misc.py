from hachoir_metadata.metadata import Metadata, registerExtractor
from hachoir_parser.misc import TorrentFile, TrueTypeFontFile, OLE2_File
from hachoir_core.error import warning

class TorrentMetadata(Metadata):
    KEY_TO_ATTR = {
        u"announce": "url",
        u"comment": "comment",
        u"creation_date": "creation_date",
    }
    INFO_TO_ATTR = {
        u"length": "file_size",
        u"name": "filename",
    }

    def extract(self, torrent):
        for field in torrent[0]:
            if field.name in self.KEY_TO_ATTR:
                key = self.KEY_TO_ATTR[field.name]
                value = field.value
                setattr(self, key, value)
            elif field.name == "info" and "value" in field:
                self.processInfo(field["value"])
    def processInfo(self, info):
        for field in info:
            if field.name in self.INFO_TO_ATTR:
                key = self.INFO_TO_ATTR[field.name]
                value = field.value
                setattr(self, key, value)
            elif field.name == "piece_length":
                self.comment = "Piece length: %s" % field.display

class TTF_Metadata(Metadata):
    NAMEID_TO_ATTR = {
        0: "copyright",   # Copyright notice
        3: "title",       # Unique font identifier
        5: "version",     # Version string
        8: "author",      # Manufacturer name
        11: "url",        # URL Vendor
        14: "copyright",  # License info URL
    }

    def extract(self, ttf):
        if "header" in ttf:
            self.extractHeader(ttf["header"])
        if "names" in ttf:
            self.extractNames(ttf["names"])

    def extractHeader(self, header):
        self.creation_date = header["created"].value
        self.last_modification = header["modified"].value
        self.comment = "Smallest readable size in pixels: %s pixels" % header["lowest"].value
        self.comment = "Font direction: %s" % header["font_dir"].display

    def extractNames(self, names):
        offset = names["offset"].value
        for header in names.array("header"):
            key = header["nameID"].value
            foffset = offset + header["offset"].value
            field = names.getFieldByAddress(foffset*8)
            if not field:
                continue
            value = field.value
            if key not in self.NAMEID_TO_ATTR:
                continue
            key = self.NAMEID_TO_ATTR[key]
            if key == "version" and value.startswith(u"Version "):
                # "Version 1.2" => "1.2"
                value = value[8:]
            setattr(self, key, value)

class OLE2_Metadata(Metadata):
    SUMMARY_ID_TO_ATTR = {
         2: ("title", False),
         4: ("author", False),
         6: ("comment", False),
         8: ("author", False),
         9: ("version", True), # Revision number
        12: ("creation_date", False),
        13: ("last_modification", False),
        14: ("nb_page", False),
        15: ("comment", True), # Nb. words
        16: ("comment", True), # Nb. characters
        18: ("producer", False),
    }

    def extract(self, ole2):
        if "summary[0]" in ole2:
            self.useSummary(ole2["summary[0]"])

    def useSummary(self, summary):
        if "section[0]" not in summary:
            return
        summary = summary["section[0]"]
        for property in summary.array("property_index"):
            field = summary.getFieldByAddress(property["offset"].value*8)
            if not field:
                print "Unable to get value"
                continue
            if not field.hasValue():
                continue
            value = field.value
            try:
                key, use_prefix = self.SUMMARY_ID_TO_ATTR[property["id"].value]
            except LookupError:
#                warning("Skip %s[%s]=%s" % (
#                    property["id"].display, property["id"].value, value))
                continue
            if use_prefix:
                value = "%s: %s" % (property["id"].display, value)
            setattr(self, key, value)

registerExtractor(TorrentFile, TorrentMetadata)
registerExtractor(TrueTypeFontFile, TTF_Metadata)
registerExtractor(OLE2_File, OLE2_Metadata)

