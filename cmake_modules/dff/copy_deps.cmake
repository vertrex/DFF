if (WIN32)

  if (POPPLERQT4_PATH)
    message(STATUS "Poppler qt4 path: ${POPPLERQT4_PATH}")
    file(GLOB popplerqt4_dyn_libraries ${POPPLERQT4_PATH}/*.dll)
    foreach(popplerqt4_dynlib ${popplerqt4_dyn_libraries})
      install_rule(${popplerqt4_dynlib})
    endforeach()
    file(GLOB popplerqt4_dyn_libraries ${POPPLERQT4_PATH}/*.pyd)
    foreach(popplerqt4_dynlib ${popplerqt4_dyn_libraries})
      install_rule(${popplerqt4_dynlib})
    endforeach()
  else (POPPLERQT4_PATH)
    message(STATUS "Poppler qt4 libraries not set. Pdf viewer disabled")
  endif (POPPLERQT4_PATH)  
  
endif (WIN32)