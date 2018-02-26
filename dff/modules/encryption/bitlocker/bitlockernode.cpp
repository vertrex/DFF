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

#include "libbde.h"

#include "typesconv.hpp"
#include "bitlockernode.hpp"
#include "exceptions.hpp"
#include "datetime.hpp"

BitLockerVolumeNode::BitLockerVolumeNode(libbde_volume_t* volume, Node* parent, fso* _fso) : Node("bitlocker", 0, parent, _fso), __volume(volume), __creationTime(NULL), __encryptionMethod("Unknown"), __volumeIdentifier("Unknown"), __description("Unknown")
{
  this->__setVolumeInfo();
}

BitLockerVolumeNode::~BitLockerVolumeNode()
{
  delete this->__creationTime;
}

std::string     BitLockerVolumeNode::__toGuid(uint8_t* guid)
{
  std::ostringstream guidStream;
  uint64_t swaped = bytes_swap64(*(uint64_t*)(guid + 8));

  guidStream << std::hex << *((uint32_t*)(guid)) << "-" << *((uint16_t*)(guid + 4)) << "-" <<  *((uint16_t*)(guid + 6)) << "-" 
                         << *((uint16_t*)((uint8_t*)&swaped + 6)) << "-" << (swaped &  0x0000ffffffffffffull);

  return (guidStream.str());
}

void            BitLockerVolumeNode::__setVolumeInfo(void)
{
  libbde_error_t* bdeError = NULL;

  uint64_t size = 0;
  if (libbde_volume_get_size(this->__volume, &size, &bdeError) != 1)
    throw vfsError("Can't get volume size");
  this->setSize(size);

  uint16_t encryptionMethod = 0;
  if (libbde_volume_get_encryption_method(this->__volume, &encryptionMethod, &bdeError) == 1)
  {
    if ((encryptionMethod & 0xffff) == LIBBDE_ENCRYPTION_METHOD_AES_128_CBC_DIFFUSER)
      this->__encryptionMethod = "AES 128-bit with diffuser";
    else if ((encryptionMethod & 0xffff) == LIBBDE_ENCRYPTION_METHOD_AES_256_CBC_DIFFUSER) 
      this->__encryptionMethod = "AES 256-bit with Diffuser";
    else if ((encryptionMethod & 0xffff) == LIBBDE_ENCRYPTION_METHOD_AES_128_CBC)
      this->__encryptionMethod = "AES 128-bit";
    else if ((encryptionMethod & 0xffff) == LIBBDE_ENCRYPTION_METHOD_AES_256_CBC)
      this->__encryptionMethod = "AES 256-bit";
  } 
 
  uint8_t volumeIdentifier[16];
  if (libbde_volume_get_volume_identifier(this->__volume, volumeIdentifier, 16, &bdeError) == 1)
    this->__volumeIdentifier = this->__toGuid(volumeIdentifier); 

  uint64_t fileTime = 0;
  if (libbde_volume_get_creation_time(this->__volume, &fileTime, &bdeError) == 1)
    this->__creationTime = new MS64DateTime(fileTime);

  size_t bufferSize = 0;
  if (libbde_volume_get_utf8_description_size(this->__volume, &bufferSize, &bdeError) == 1)
  {
    uint8_t* buffer = new uint8_t[bufferSize];
    if (libbde_volume_get_utf8_description(this->__volume, buffer, bufferSize, &bdeError) == 1)
      this->__description = std::string((char*)buffer, bufferSize);
    delete[] buffer;
  }

  int keyProtectorsCount = 0;
  if (libbde_volume_get_number_of_key_protectors(this->__volume, &keyProtectorsCount, &bdeError) == 1)
  {
    for (int keyProtectorIndex = 0; keyProtectorIndex < keyProtectorsCount; keyProtectorIndex++)
    {
      std::string       guid;
      std::string       keyProtectorType;
      libbde_key_protector_t*   keyProtector = NULL;

      if (libbde_volume_get_key_protector(this->__volume, keyProtectorIndex, &keyProtector, &bdeError) == 1)
      {
        uint8_t identifier[16]; 
        if (libbde_key_protector_get_identifier(keyProtector, identifier, 16, &bdeError) == 1)
          guid = this->__toGuid(identifier);
        uint16_t type = 0;
        if (libbde_key_protector_get_type(keyProtector, &type, &bdeError) == 1)
        {
          if (type == LIBBDE_KEY_PROTECTION_TYPE_CLEAR_KEY)
            keyProtectorType = "Clear key";
          else if (type == LIBBDE_KEY_PROTECTION_TYPE_TPM)
            keyProtectorType = "TPM";
          else if (type == LIBBDE_KEY_PROTECTION_TYPE_STARTUP_KEY)
            keyProtectorType = "Startup key";
          else if (type == LIBBDE_KEY_PROTECTION_TYPE_RECOVERY_PASSWORD)
            keyProtectorType = "Recovery password";
          else if (type == LIBBDE_KEY_PROTECTION_TYPE_PASSWORD)
            keyProtectorType = "Password";
          else
            keyProtectorType = "Unknown";
        }

        std::map<std::string, Variant_p> keyProtectorAttributes;
        keyProtectorAttributes["Identifier"] = new Variant(guid);
        keyProtectorAttributes["Type"] = new Variant(keyProtectorType);
        this->__keyProtector.push_back(Variant_p(new Variant(keyProtectorAttributes)));

        libbde_key_protector_free(&keyProtector, &bdeError);
      }
    }
  } 
}

Attributes      BitLockerVolumeNode::_attributes(void)
{
  Attributes    attributes;
 
  if (this->__creationTime)
    attributes["Creation time"] = Variant_p(new Variant(this->__creationTime));
  attributes["Encryption method"] = Variant_p(new Variant(this->__encryptionMethod));
  attributes["Volume identifer"] = Variant_p(new Variant(this->__volumeIdentifier));
  attributes["Description"] = Variant_p(new Variant(this->__description));
  attributes["Key protector"] = Variant_p(new Variant(this->__keyProtector));

  return (attributes);
}
