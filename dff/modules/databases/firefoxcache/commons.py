from dff.modules.firefoxcache.decoder import *

CACHE_MAP = "_CACHE_MAP_"
CACHE_001 = "_CACHE_001_"
CACHE_002 = "_CACHE_002_"
CACHE_003 = "_CACHE_003_"

BUCKETS = 32

HEADER_BUCKETS = (BUCKETS * 2) * 4
HEADER_SIZE = 0x14 + HEADER_BUCKETS

CACHE = [CACHE_MAP, CACHE_001, CACHE_002, CACHE_003]

FIREFOX_MAP_HEADER = {
    "version" : [0x0, 0x4, UINT32_T],
    "dataSize" : [0x4, 0x4, UINT32_T],
    "entryCount" : [0x8, 0x4, INT32_T],
    "isDirty" : [0xC, 0x4, UINT32_T],
    "recordCount" : [0x10, 0x4, INT32_T]}

#    "evictionRank" : [0x14, 0x4, UINT32_T],
#    "bucketUsage" : [0x18, 0x4, UINT32_T]}

FIREFOX_MAP_RECORD = {
    "hash" : [0x0, 0x4, UINT32_T],
    "evictionRank" : [0x4, 0x4, UINT32_T],
    "dataLocation" : [0x8, 0x4, UINT32_T],
    "metaLocation" : [0xC, 0x4, UINT32_T]}

FIREFOX_META_ENTRY = {
    "headerVersion" : [0x0, 0x4, UINT32_T],
    "metaLocation" : [0x4, 0x4, UINT32_T],
    "fetchCount" : [0x8, 0x4, INT32_T],
    "lastFetched" : [0xC, 0x4, UINT32_T],
    "lastModified" : [0x10, 0x4, UINT32_T],
    "expirationTime" : [0x14, 0x4, UINT32_T],
    "dataSize" : [0x18, 0x4, UINT32_T],
    "keySize" : [0x1C, 0x4, UINT32_T],
    "metaDataSize" : [0x20, 0x4, UINT32_T]}

LocationInitializedMask = 0x80000000
LocationSelectorMask    = 0x30000000
LocationSelectorOffset  = 28
ExtraBlocksMask         = 0x03000000
ExtraBlocksOffset       = 24
ReservedMask            = 0x4C000000
BlockNumberMask         = 0x00FFFFFF
FileSizeMask            = 0x00FFFF00
FileSizeOffset          = 8
FileGenerationMask      = 0x000000FF
FileReservedMask        = 0x4F000000

