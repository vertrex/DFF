/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal J. <sja@digital-forensic.org>
 */

#include "pyrun.swg"

%module(package="api.gui.video", docstring="video api to extract thumbnail and metadata")  video 
%feature("autodoc", 1);
%feature("docstring") DFF::VideoDecoder::VideoDecoder
"
Initialize VideoDecoder class, take a Node as parameter.
If error occurs throw an std::string containg error message.
"

%feature("docstring") DFF::VideoDecoder::width
"
Return video width or -1 if video can't be decoded. 
"

%feature("docstring") DFF::VideoDecoder::height
"
Return video height or -1 if video can't be decoded.
"

%feature("docstring") DFF::VideoDecoder::duration
"
Return video duration in seconds or 0 if video can't be decoded.
"

%feature("docstrng") DFF::VideoDecoder::codec
"
Return a string containing the video codec name.
"

%feature("docstring") DFF::VideoDecoder::thumbnailAt
"
Take a time in seconds and scale size as parameters.
Return a QImage containg a thumbnail of the video at time x in seconds, scaled size by default is 64.
Returned class use ref counting.
If error occurs throw a std::string containing error message.
"

%feature("docstring") DFF::VideoDecoder::thumbnailAtPercent
"
Take a percent of video length and scale size as parameters.
Return a QImage containg a thumbnail of the video at percent x of the duration, scaled size by default is 64.
Returned class use ref counting.
If error occurs throw a std::string containing error message.
"

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%typemap(out) DFF::ImageData
{
  $result = PyString_FromStringAndSize((const char*)$1.buff, $1.size);
}

%newobject      DFF::VideoDecoder::thumbnail;
%newobject      DFF::VideoDecoder::thumbnailAt;
%newobject      DFF::VideoDecoder::thumbnailAtPercent;

%pythoncode
{
from PyQt4.QtGui import QImage
}

%pythonappend DFF::VideoDecoder::thumbnailAt 
%{ 
   return QImage(val.data(), val.width(), val.height(), 5)  
%}

%pythonappend DFF::VideoDecoder::thumbnailAtPercent 
%{
  return QImage(val.data(), val.width(), val.height(), 5)
%}

%{
#include "export.hpp"
#include "rc.hpp"
#include "video.hpp"
%}

%refobject DFF::RCObj "$this->addref();"
%unrefobject DFF::RCObj "$this->delref();"
%import "../../exceptions/libexceptions.i"

%include "export.hpp"
%include "rc.hpp"
%include "video.hpp"


%extend_smart_pointer(Image_p);
%template(RCPtrImage) Image_p;
