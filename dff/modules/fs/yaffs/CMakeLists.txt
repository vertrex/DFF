include_directories(${ICU_INCLUDE_DIRS})

dff_cpp_module(yaffs
  CPP_FILES yaffs.cpp 
  tags.cpp 
  object_node.cpp

  SWIG_FILE yaffs.i
  INCLUDE_DIRS ${ICU_INCLUDE_DIRS} 
  LINK_LIBRARIES ${ICU_LIBRARIES} exceptions types vfs
)
