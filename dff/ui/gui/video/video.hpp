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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __VIDEO_HH__
#define __VIDEO_HH__
#include <string>
#include <iostream>
#include <stdio.h>
#include <list>

#include "exceptions.hpp"
#include "export.hpp"
#include "rc.hpp"

extern "C"
{
#ifndef INT64_C
  #define  INT64_C(c) (c ## LL)
  #define UINT64_C(c) (c ## ULL)
#endif

#include <libavformat/avio.h>
#include <libavformat/avformat.h>
#include <libavutil/mem.h>
#ifdef LATEST_GREATEST_FFMPEG
#include <libavutil/opt.h>
#endif
#include <libswscale/swscale.h>
}

namespace DFF
{
class Node; 
class VFile;


struct  ImageData
{
  char*         buff;
  uint32_t      size;
} ;


class Image : public RCObj
{
private:
  ImageData      _data;
  int32_t	 _width;
  int32_t	 _height;
public:
  EXPORT		Image(uint8_t* idata, uint32_t size, int32_t width, int32_t height);
  EXPORT    		~Image(void);
  EXPORT ImageData	data(void);
  EXPORT int32_t	height(void);
  EXPORT int32_t	width(void);
};

#define Image_p DFF::RCPtr< DFF::Image > 

class	VideoDecoder
{
private:
  VFile*		_file;
  AVFormatContext*	_formatContext;
  AVIOContext*		_IOContext;
  AVCodecContext*	_codecContext;
  AVCodec*		_codec;
  AVStream*		_stream;
  AVFrame*		_frame;
  AVPacket*		_packet;
  unsigned char*	_buffer;
  uint8_t*		_frameBuffer;
  int			_videoStream;

  void 			_clear();
  void			_initializeVideo(void); 
  void			_decodeVideoFrame(void);
  bool			_decodeVideoPacket(void);
  bool			_getVideoPacket(void);
  void			_seek(int64_t seconds);
  void			_convertAndScaleFrame(AVPixelFormat format, int scaledSize, bool maintainAspectRatio, int &scaledWidth, int &scaledHeight);
  void 			_calculateDimensions(int squareSize, bool maintainAspectRatio, int& destWidth, int& destHeight);
  void 			_createAVFrame(AVFrame** pAvFrame, uint8_t** pFrameBuffer, int width, int height, AVPixelFormat format);
  Image_p		_thumbnail(int32_t scale = 64);
public:
  EXPORT 			VideoDecoder(Node* node);
  EXPORT 		  	~VideoDecoder(void);
  EXPORT  int32_t		width(void);
  EXPORT  int32_t		height(void);
  EXPORT  int32_t		duration(void);
  EXPORT  std::string		codec(void);
  EXPORT  Image_p		thumbnailAtPercent(uint8_t timeInPercent, int32_t scaledSize = 64);
  EXPORT  Image_p		thumbnailAt(int64_t timeInSeconds, int32_t scaledSize = 64);

};

}
#endif 
