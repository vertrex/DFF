AUTORUNS = {"HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce" : ["*"],
            "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\Explorer\Run" : ["*"],
            "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" : ["*"],
            "HKU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run" : ["*"],
            "HKU\Software\Microsoft\Windows\CurrentVersion\Run" : ["*"],
            "HKU\Software\Microsoft\Windows\CurrentVersion\RunOnce" : ["*"]}

USB = {"HKU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoint2\*" : ["*"]}

EXPLORER = {"HKU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" : ["*"],
            "HKU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count" : ["*"],
            "HKU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" : ["*"],
            "HKU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" : ["*"]}


INTERNET_EXPLORER = {"HKU\Software\Microsoft\Internet Explorer\Main" : ["*"],
                     "HKU\Software\Microsoft\Internet Explorer\TypedURLs" : ["*"],
                     "HKU\Software\Microsoft\Internet Explorer" : ["Download Directory"]}

DEFAULT_BROWSER = {"HKUCL\http\shell\open\command" : ["*"]}


TYPEDURL = {"HKU\Software\Microsoft\Internet Explorer\TypedURLs" : ["*"]}



#TEST = ["HKLM\SYSTEM\ControlSet*\Services\*"]


###################
# SQLITE COMMANDS #
###################


FX_PLACES2 = "SELECT url, title, rev_host, visit_count, hidden, typed, favicon_id, frecency, last_visit_date FROM moz_places;"

FX_PLACES = "select moz_places.url, moz_places.title, moz_places.rev_host, moz_places.visit_count, moz_places.hidden, moz_places.typed, moz_places.frecency, moz_historyvisits.visit_date from moz_places, moz_historyvisits where moz_historyvisits.place_id=moz_places.id;"

FX_INPUT2 = "SELECT fieldname, value, timesUsed, firstUsed, lastUsed from moz_formhistory;"

FX_INPUT = "SELECT fieldname, value from moz_formhistory;"
