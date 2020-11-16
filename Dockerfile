FROM ubuntu:16.04

LABEL Description="build DFF on ubuntu 16.04"

# Dependencies of the Qt offline installer
RUN apt update \
	&& apt upgrade -y \
	&& apt install -y \
	build-essential cmake libafflib0v5  libafflib-dev libicu55 libicu-dev libtre5 libtre-dev pyqt4-dev-tools python-qt4 swig libpython-dev git qt4-dev-tools python-dbus python-pil python-apsw volatility clamav subversion scons libtalloc-dev automake autopoint libtool bison flex libfuse-dev libarchive-dev libavcodec-ffmpeg56 libavdevice-dev libavcodec-dev libavcodec-extra libavformat-dev libavutil-dev 

RUN mkdir src
RUN cd /src && git clone https://github.com/libyal/libbfio.git 
RUN cd /src && git clone https://github.com/libyal/libewf.git
RUN cd /src && git clone https://github.com/libyal/libpff.git
RUN cd /src && git clone https://github.com/libyal/libvshadow.git
RUN cd /src && git clone https://github.com/libyal/libqcow.git 
RUN cd /src && git clone https://github.com/libyal/libbde.git
RUN cd /src && svn co https://code.blindspotsecurity.com/dav/reglookup/ 
RUN cd /src && git clone git://digital-forensic.org/dff-2.git 

RUN cd /src/libbfio && ./synclibs.sh && ./autogen.sh && ./configure --prefix=/usr && make install -j `nproc`
RUN cd /src/libewf && ./synclibs.sh && ./autogen.sh && ./configure --prefix=/usr --with-libbfio=/usr/lib && make install -j `nproc`
RUN cd /src/libvshadow && ./synclibs.sh && ./autogen.sh && ./configure --prefix=/usr --with-libbfio=/usr/lib && make install -j `nproc`
RUN cd /src/libqcow && ./synclibs.sh && ./autogen.sh && ./configure --prefix=/usr --with-libbfio=/usr/lib && make install -j `nproc`
RUN cd /src/libbde && ./synclibs.sh && ./autogen.sh && ./configure --prefix=/usr --with-libbfio=/usr/lib && make install -j `nproc`
RUN cd /src/libpff && ./synclibs.sh && ./autogen.sh && ./configure --prefix=/usr --with-libbfio=/usr/lib && make install -j `nproc`
RUN cd /src/reglookup/releases/1.0.1 && scons install && cd / 


RUN cd /src/dff-2 && mkdir build && cd build && cmake .. && make -j `nproc` && make install 
RUN echo "#!/bin/bash\nQT_X11_NO_MITSHM=1 dff-gui" > /usr/sbin/launch-dff && chmod +x /usr/sbin/launch-dff 
#rm -rf ~/src ? et creat other docker ?
#ENTRYPOINT ["/bin/bash"]
ENTRYPOINT ["/usr/sbin/launch-dff"]
