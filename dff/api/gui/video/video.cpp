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
/*
 * Most of code come from libffmpegthumbnailer by
 * Dirk Vanden Boer <dirk.vdb@gmail.com>
*/

#include "node.hpp"
#include "vfile.hpp"
#include "video.hpp"
#include <libavcodec/avcodec.h>

#if _MSC_VER >= 1800
#include <algorithm>
#endif

namespace DFF
{

Image::Image(uint8_t* idata, uint32_t size, int32_t width, int32_t height)
{
  this->_data.size = size;
  this->_data.buff = (char*)malloc(size); 
  memcpy(this->_data.buff, idata, size);
  this->_width = width;
  this->_height = height;
}

Image::~Image(void)
{
  free(this->_data.buff);
}

ImageData Image::data(void)
{
  return (this->_data);
}

int32_t Image::width(void)
{
  return (this->_width);
} 

int32_t Image::height(void)
{
  return (this->_height);
}

extern "C" 
{
  int FFMpegRead(void* opaque, uint8_t* buf, int size)
  {
    VFile* file = (VFile*)opaque;

    if (file == NULL)
      return (-1);

    return (file->read(buf, size));
  }

  int64_t FFMpegSeek(void* opaque, int64_t offset, int whence)
  {
    VFile* file = (VFile*)opaque;

    if (file == NULL)
      return (-1);

    if (whence == AVSEEK_SIZE)
      return ((int64_t)file->node()->size());

    return ((int64_t)file->seek((uint64_t)offset, whence));
   }
}

VideoDecoder::VideoDecoder(Node* node)
{
  this->_file = NULL;
  this->_buffer = NULL;
  this->_IOContext = NULL;
  this->_formatContext = NULL;
  this->_codecContext = NULL;
  this->_codec = NULL;
  this->_stream = NULL;
  this->_frame = NULL;
  this->_packet = NULL;
  this->_videoStream = -1;
  this->_frameBuffer = NULL;

  if (node == NULL)
  {
    this->_clear();
    throw std::string("VideoDecoder Node is NULL");
  }

  try 
  {
    if (node->size() > 0)
    {
      this->_file = node->open();
      this->_buffer = (unsigned char *)av_malloc(4096*640);
      if (this->_buffer == NULL)
      {
	this->_clear();
        throw std::string("Can't allocate buffer");
      }
    }
    this->_IOContext = avio_alloc_context(this->_buffer, 4096*640, 0, this->_file, FFMpegRead, NULL, FFMpegSeek);
  }
  catch (...)
  {
     this->_clear();
     av_free(this->_buffer);
     throw std::string("Error can't init class");
  }

  av_register_all();
  avcodec_register_all();
  av_log_set_level(-8);
 
  this->_formatContext = avformat_alloc_context();
  this->_formatContext->pb = this->_IOContext;
  if (avformat_open_input(&(this->_formatContext), node->name().c_str(), NULL, NULL) != 0)
  {
	this->_clear();	
        throw std::string("can't open input stream");
  }
  if (avformat_find_stream_info(this->_formatContext, NULL) < 0)
  {
	this->_clear();
	throw std::string("can't find video info");
  }

  this->_initializeVideo();
  this->_frame = av_frame_alloc();
}

VideoDecoder::~VideoDecoder()
{
  this->_clear();
}

void	VideoDecoder::_clear(void)
{
  //error in ffmpeg av_close_input_file fail to free IOContext buff causing memory leak
  //maybe didn't find the AVFMT_FLAG_CUSTOM_IO
  if (this->_IOContext)
  {
    if (this->_IOContext->buffer)
    {
      av_free(this->_IOContext->buffer);
      this->_IOContext->buffer = NULL;
    } 
    av_free(this->_IOContext);
    this->_IOContext = NULL;
  }
  if (this->_codecContext)
  {
    avcodec_close(this->_codecContext);
    this->_codecContext = NULL;
  }
  if (this->_formatContext)
  {
    avformat_close_input(&this->_formatContext);
    this->_formatContext = NULL;
  }
  if (this->_codec) //return by avcodec_find_decoder not allocated ?
    this->_codec = NULL;
  if (this->_stream)
    this->_stream = NULL;
  if (this->_frame)
    av_free(this->_frame);
  if (this->_frameBuffer)
    av_free(this->_frameBuffer);
  if (this->_packet)
  {
    av_free_packet(this->_packet);
    delete this->_packet;
    this->_packet = NULL;
  }
  if (this->_file)
    this->_file->close();
  delete this->_file;
}

void VideoDecoder::_convertAndScaleFrame(AVPixelFormat format, int scaledSize, bool maintainAspectRatio, int& scaledWidth, int& scaledHeight)
{
    this->_calculateDimensions(scaledSize, maintainAspectRatio, scaledWidth, scaledHeight);

#ifdef LATEST_GREATEST_FFMPEG
	// Enable this when it hits the released ffmpeg version
    SwsContext* scaleContext = sws_alloc_context();
    if (scaleContext == NULL)
      throw std::logic_error("Failed to allocate scale context");
	
    av_set_int(scaleContext, "srcw", this->_codecContext->width);
    av_set_int(scaleContext, "srch", this->_codecContext->height);
    av_set_int(scaleContext, "src_format", this->_codecContext->pix_fmt);
    av_set_int(scaleContext, "dstw", scaledWidth);
    av_set_int(scaleContext, "dsth", scaledHeight);
    av_set_int(scaleContext, "dst_format", format);
    av_set_int(scaleContext, "sws_flags", SWS_BICUBIC);
	
    const int* coeff = sws_getCoefficients(SWS_CS_DEFAULT);
    if (sws_setColorspaceDetails(scaleContext, coeff, this->_codecContext->pix_fmt, coeff, format, 0, 1<<16, 1<<16) < 0)
    {
      sws_freeContext(scaleContext);
      throw std::logic_error("Failed to set colorspace details");
    }

    if (sws_init_context(scaleContext, NULL, NULL) < 0)
    {
       sws_freeContext(scaleContext);
       throw std::logic_error("Failed to initialise scale context");
    }
#endif
    
    SwsContext* scaleContext = sws_getContext(this->_codecContext->width, this->_codecContext->height,
                                              this->_codecContext->pix_fmt, scaledWidth, scaledHeight,
                                              format, SWS_BICUBIC, NULL, NULL, NULL);

    if (scaleContext == NULL)
    {
      throw std::string("Failed to create resize context");
    }

    AVFrame* convertedFrame = NULL;
    uint8_t* convertedFrameBuffer = NULL;

    this->_createAVFrame(&convertedFrame, &convertedFrameBuffer, scaledWidth, scaledHeight, format);
    
    sws_scale(scaleContext, this->_frame->data, this->_frame->linesize, 0, this->_codecContext->height,
              convertedFrame->data, convertedFrame->linesize);
    sws_freeContext(scaleContext);

    av_free(this->_frame);
    av_free(this->_frameBuffer);
    
    this->_frame        = convertedFrame;
    this->_frameBuffer  = convertedFrameBuffer;
}

void VideoDecoder::_calculateDimensions(int squareSize, bool maintainAspectRatio, int& destWidth, int& destHeight)
{
    if (squareSize == 0)
    {
        #undef max // Fixes Windows compilation error C2589, some other header
	           // file is polluting the global name space  with a max
		   // macro.
        squareSize = std::max(this->_codecContext->width, this->_codecContext->height);
    }
    
    if (!maintainAspectRatio)
    {
        destWidth = squareSize;
        destHeight = squareSize;
    }
    else
    {
        int srcWidth            = this->_codecContext->width;
        int srcHeight           = this->_codecContext->height;
        int ascpectNominator    = this->_codecContext->sample_aspect_ratio.num;
        int ascpectDenominator  = this->_codecContext->sample_aspect_ratio.den;
        
        if (ascpectNominator != 0 && ascpectDenominator != 0)
        {
            srcWidth = srcWidth * ascpectNominator / ascpectDenominator;
        }
        
        if (srcWidth > srcHeight)
        {
            destWidth  = squareSize;
            destHeight = static_cast<int>(static_cast<float>(squareSize) / srcWidth * srcHeight);
        }
        else
        {
            destWidth  = static_cast<int>(static_cast<float>(squareSize) / srcHeight * srcWidth);
            destHeight = squareSize;
        }
    }
}

void VideoDecoder::_createAVFrame(AVFrame** pAvFrame, uint8_t** pFrameBuffer, int width, int height, AVPixelFormat format)
{
    *pAvFrame = av_frame_alloc();

    int numBytes = avpicture_get_size(format, width, height);
    *pFrameBuffer = reinterpret_cast<uint8_t*>(av_malloc(numBytes));
    avpicture_fill((AVPicture*) *pAvFrame, *pFrameBuffer, format, width, height);
}

void 	VideoDecoder::_seek(int64_t seconds)
{
	//if allowSEek return ?
  int64_t timestamp = AV_TIME_BASE * seconds;
 
  if (timestamp < 0)
    timestamp = 0;
 
  if (av_seek_frame(this->_formatContext, -1, timestamp, 0) >= 0)
    avcodec_flush_buffers(this->_formatContext->streams[this->_videoStream]->codec);
  else
    throw std::string("Seek failed");

  int  keyFrameAttempts = 0;
  bool gotFrame = 0;

  do
  {
     int count = 0;
     gotFrame = 0;

     while (!gotFrame && count < 20)
     {
        this->_getVideoPacket();
        try
        {
          gotFrame = this->_decodeVideoPacket();
        }
        catch (...) {}
	++count;
     }
     ++keyFrameAttempts;  
   } while ((!gotFrame || !this->_frame->key_frame) && keyFrameAttempts < 200);

   if (gotFrame == 0)
     throw std::string("Can't seek in video");

}

void	VideoDecoder::_decodeVideoFrame()
{
   bool frameFinished = false;

   while (!frameFinished && this->_getVideoPacket())
	frameFinished = this->_decodeVideoPacket();

   if (!frameFinished)
     throw std::string("decodeVideoFrame : frame not finished");
}

bool	VideoDecoder::_decodeVideoPacket()
{
   if (this->_packet->stream_index != this->_videoStream)
     return false;

   av_frame_unref(this->_frame);

   int frameFinished;
   int bytesDecoded = avcodec_decode_video2(this->_codecContext, this->_frame, &frameFinished, this->_packet);
   if (bytesDecoded < 0)
     throw std::string("fail to decode video frame");

   return (frameFinished > 0);
}

bool	VideoDecoder::_getVideoPacket(void)
{
  bool framesAvailable = true;
  bool frameDecoded = false;
  int  attempts = 0;

  if (this->_packet)
  {
    av_free_packet(this->_packet);
    delete this->_packet;
  }
  this->_packet = new AVPacket();
  
  while (framesAvailable && !frameDecoded && (attempts++ < 1000))
  {
     if (av_read_frame(this->_formatContext, this->_packet) >= 0)
	framesAvailable = true;
     else
	framesAvailable = false;
     if (framesAvailable)
     {
       frameDecoded = this->_packet->stream_index == this->_videoStream;
       if (!frameDecoded)
       {
	 av_free_packet(this->_packet);
       }
     }
  }

  return (frameDecoded);
}

void 	VideoDecoder::_initializeVideo()
{
  unsigned int i = 0;

  for (; i < this->_formatContext->nb_streams; i++)
  {
#if LIBAVCODEC_VERSION_MAJOR < 53
     if (this->_formatContext->streams[i]->codec->codec_type == CODEC_TYPE_VIDEO)
#else
     if (this->_formatContext->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO)
#endif     
     {
       this->_stream = this->_formatContext->streams[i];
       this->_videoStream = i;
       break;
     } 
  }
 
  if (this->_videoStream < 0)
  {
    this->_clear();
    throw std::string("Could not find video stream");
  }
  this->_codecContext = this->_formatContext->streams[this->_videoStream]->codec;
  this->_codec = avcodec_find_decoder(this->_codecContext->codec_id);

  if (this->_codec == NULL)
  {
    this->_codecContext = NULL;
    this->_clear();
    throw std::string("Codec not found, can't decode");
  }

  this->_codecContext->workaround_bugs = 1;
  if (avcodec_open2(this->_codecContext, this->_codec, NULL) < 0)
  {
    this->_clear();
    throw std::string("Could not open video");
  }
}

Image_p		VideoDecoder::_thumbnail(int32_t scaledSize)
{
  int scaledHeight, scaledWidth;
  bool maintainAspectRatio = 0;

  //if (this->_frame->interlaced_frame)
  //  avpicture_deinterlace((AVPicture*) this->_frame, (AVPicture*) this->_frame, this->_codecContext->pix_fmt, 
  //			  this->_codecContext->width, this->_codecContext->height);

  this->_convertAndScaleFrame(AV_PIX_FMT_RGB32, scaledSize, maintainAspectRatio, scaledWidth, scaledHeight);
  Image_p	image(new Image(this->_frame->data[0], this->_frame->linesize[0] * scaledHeight, scaledWidth, scaledHeight));

  return (image);
}

Image_p		VideoDecoder::thumbnailAt(int64_t seconds, int32_t scaledSize)
{
	//try {
  this->_decodeVideoFrame(); 
  this->_seek(seconds);
  //}
  //catch (std::string e)
  //{
  //cout << "error " << endl;
  ////this->_clear();
  //this->_seek(0);
  //this->_initializeVideo();
  //this->_decodeVideoFrame();
  //}

  return (this->_thumbnail(scaledSize));
}

Image_p		VideoDecoder::thumbnailAtPercent(uint8_t percent, int32_t scaledSize)
{
  //check if 0 > x < 100 %
  int64_t seconds = ((int64_t) ((float)this->duration() * (percent/100.00)));
  return (this->thumbnailAt(seconds, scaledSize));
}

int32_t VideoDecoder::width()
{
  if (this->_codecContext)
    return (this->_codecContext->width);
  return (-1);
}

int32_t VideoDecoder::height()
{
  if (this->_codecContext)
    return (this->_codecContext->height);
  return (-1);
}

int32_t VideoDecoder::duration()
{
  if (this->_formatContext)
    return (this->_formatContext->duration / AV_TIME_BASE);
  return (0);
}

std::string VideoDecoder::codec()
{
  if (this->_codec)
  {
    return std::string(this->_codec->name);
  }
  return std::string("");
}

}
