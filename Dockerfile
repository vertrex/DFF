FROM ubuntu:16.04

LABEL Description="build DFF on ubuntu 16.04"

# Dependencies of the Qt offline installer
RUN apt update \
	&& apt upgrade -y \
	&& apt install -y \
	apt-utils build-essential cmake libafflib0v5  libafflib-dev libavcodec-dev libavcodec-extra libavformat-dev libavutil-dev libbfio-dev libbfio1 libewf-dev libfuse-dev libicu55 libicu-dev libpff1 libpff-dev libtre5 libtre-dev pyqt4-dev-tools python-qt4 swig libpython-dev git libqcow-dev libqcow1 qt4-dev-tools python-dbus python-pil python-apsw volatility clamav 

#add elastic search indexer ?
#install clamav && update db ?
#libreoffice -> no python2 bindings in ubuntu (should try a debian build ?)
#pyregfi
#video api ?

RUN git clone git://digital-forensic.org/dff-2.git && cd dff-2 && mkdir build &&cd build && cmake .. && make && make install 
RUN echo "#!/bin/bash\nQT_X11_NO_MITSHM=1 dff-gui" > /usr/sbin/launch-dff && chmod +x /usr/sbin/launch-dff 
#ENTRYPOINT ["/bin/bash"]
ENTRYPOINT ["/usr/sbin/launch-dff"]
