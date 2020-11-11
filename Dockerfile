FROM ubuntu:14.04 
#16.04 has no webkit

LABEL Description="build DFF on ubuntu 16.04"

# Dependencies of the Qt offline installer
#RUN apt update \
	#&& apt upgrade -y \
	#&& apt install -y \
	#apt-utils build-essential cmake libafflib0v5  libafflib-dev libavcodec-dev libavcodec-extra libavformat-dev libavutil-dev libbfio-dev libbfio1 libewf-dev libfuse-dev libicu55 libicu-dev libpff1 libpff-dev libtre5 libtre-dev pyqt4-dev-tools python-qt4 swig libpython-dev git libqcow-dev libqcow1 qt4-dev-tools python-dbus python-pil python-apsw volatility clamav subversion scons libtalloc-dev

RUN apt update \
	&& apt upgrade -y \
	&& apt install -y \
	apt-utils build-essential cmake   libafflib-dev libavcodec-dev libavcodec-extra libavformat-dev libavutil-dev libbfio-dev libbfio1 libewf-dev libfuse-dev  libicu-dev libpff1 libpff-dev libtre5 libtre-dev pyqt4-dev-tools python-qt4 swig libpython-dev git  qt4-dev-tools python-dbus python-pil python-apsw volatility clamav subversion scons libtalloc-dev
#libafflib0v5
#libicu55
#libqcow-dev libqcow1

 
RUN svn co https://code.blindspotsecurity.com/dav/reglookup/ && cd reglookup/releases/1.0.1 && scons install && cd /
RUN git clone git://digital-forensic.org/dff-2.git && cd dff-2 && mkdir build &&cd build && cmake .. && make && make install 
RUN echo "#!/bin/bash\nQT_X11_NO_MITSHM=1 dff-gui" > /usr/sbin/launch-dff && chmod +x /usr/sbin/launch-dff 
#ENTRYPOINT ["/bin/bash"]
ENTRYPOINT ["/usr/sbin/launch-dff"]
