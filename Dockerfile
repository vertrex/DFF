FROM ubuntu:16.04 AS builder

LABEL Description="build DFF on ubuntu 16.04"


RUN apt update \
	&& apt upgrade -y \
	&& apt-get install -y \
	apt-utils build-essential cmake libafflib0v5  libafflib-dev libicu55 libicu-dev libtre5 libtre-dev pyqt4-dev-tools python-qt4 swig libpython-dev git qt4-dev-tools python-dbus python-pil python-apsw volatility clamav subversion scons libtalloc-dev automake autopoint libtool bison flex libfuse-dev libarchive-dev libavdevice-dev libavcodec-dev libavcodec-extra libavformat-dev libavutil-dev \
  && apt-get install -y libavcodec-ffmpeg56 

RUN mkdir src
RUN cd /src && git clone https://github.com/libyal/libbfio.git 
RUN cd /src && git clone https://github.com/libyal/libewf.git
RUN cd /src && git clone https://github.com/libyal/libpff.git
RUN cd /src && git clone https://github.com/libyal/libvshadow.git
RUN cd /src && git clone https://github.com/libyal/libqcow.git 
RUN cd /src && git clone https://github.com/libyal/libbde.git
RUN cd /src && svn co https://code.blindspotsecurity.com/dav/reglookup/ 
RUN cd /src && git clone git://digital-forensic.org/dff-2.git 

RUN cd /src/libbfio && ./synclibs.sh && ./autogen.sh && ./configure && make install -j `nproc`
RUN cd /src/libewf && ./synclibs.sh && ./autogen.sh && ./configure --with-libbfio=/usr/local/lib && make install -j `nproc`
RUN cd /src/libvshadow && ./synclibs.sh && ./autogen.sh && ./configure --with-libbfio=/usr/local/lib && make install -j `nproc`
RUN cd /src/libqcow && ./synclibs.sh && ./autogen.sh && ./configure --with-libbfio=/usr/local/lib && make install -j `nproc`
RUN cd /src/libbde && ./synclibs.sh && ./autogen.sh && ./configure --with-libbfio=/usr/local/lib && make install -j `nproc`
RUN cd /src/libpff && ./synclibs.sh && ./autogen.sh && ./configure --with-libbfio=/usr/local/lib && make install -j `nproc`
RUN cd /src/reglookup/releases/1.0.1 && scons install && cd / 

RUN cd /src/dff-2 && mkdir build && cd build && cmake .. && make -j `nproc` && make install 

FROM ubuntu:16.04 AS runtime
RUN set -ex;         \
    apt-get update -y;  \
    apt-get install -y \
    libafflib0v5  libicu55 libtre5 python-qt4 python-dbus python-pil python-apsw libfuse2 libavformat-ffmpeg56 libavdevice-ffmpeg56 libavcodec-ffmpeg56 libarchive13 volatility clamav libtalloc2

COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/share /usr/local/share
COPY --from=builder /usr/lib/python2.7/dist-packages/dff.py /usr/lib/python2.7/dist-packages/dff.py
COPY --from=builder /usr/lib/python2.7/dist-packages/dff-gui.py /usr/lib/python2.7/dist-packages/dff-gui.py
COPY --from=builder /usr/lib/python2.7/dist-packages/dff/ /usr/lib/python2.7/dist-packages/dff/
COPY --from=builder /usr/local/lib/dff /usr/local/lib/dff
COPY --from=builder /usr/local/bin/dff /usr/local/bin/dff
COPY --from=builder /usr/local/bin/dff-gui /usr/local/bin/dff-gui

RUN ldconfig

RUN echo "#!/bin/bash\nQT_X11_NO_MITSHM=1 dff-gui" > /usr/sbin/launch-dff && chmod +x /usr/sbin/launch-dff 

#ENTRYPOINT ["/bin/bash"]
ENTRYPOINT ["/usr/sbin/launch-dff"]

