### Package creation for windows platform

SET(INSTALL_FILE_DESTINATION "dff")

SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_FULL_NAME}")
SET(CPACK_PACKAGE_VENDOR "${PROJECT_VENDOR}")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYRIGHT")
# In order to provide top-level setting of DFF version, three variables bellow
# must be used in those two files :
#  ui/gui/gui.py
#  ui/ui.py
# See corresponding CMakeLists.txt for CONFIGURE_FILE.
SET(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
SET(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
SET(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "DFF")

message(STATUS "DFF target version is ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

SET(CPACK_SET_DESTDIR "OFF")

if(HAVE_64_BITS)
  SET(TARGET_PLATFORM "64")
  SET(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES64")
else()
  SET(TARGET_PLATFORM "32")
  SET(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES")
endif()

SET(CPACK_NSIS_PACKAGE_NAME "${CPACK_PACKAGE_INSTALL_DIRECTORY}")
SET(CPACK_PACKAGE_INSTALL_REGISTRY_KEY "dff")
SET(CPACK_NSIS_DISPLAY_NAME "Digital Forensics Framework ${TARGET_PLATFORM} bits")

# Install dff launchers
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${CONSOLE_SCRIPT}
        DESTINATION ${CMAKE_PROJECT_NAME}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	RENAME dff.py)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${GRAPHICAL_SCRIPT}
        DESTINATION ${CMAKE_PROJECT_NAME}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        RENAME dff-gui.pyw)


install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/ressources/dff.ico
	DESTINATION ${CMAKE_PROJECT_NAME}/ressources/)

# Install docs and licenses
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/README ${CMAKE_CURRENT_SOURCE_DIR}/COPYRIGHT ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE-THIRDPARTY
        DESTINATION ${CMAKE_PROJECT_NAME}/
        PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)


#Install third-party
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/third-party DESTINATION ${CMAKE_PROJECT_NAME})
      
      
SET(CPACK_MONOLITHIC_INSTALL "ON")
	
SET(CPACK_PACKAGE_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\ressources\\\\arxsys.bmp")
SET(CPACK_BUNDLE_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\ressources\\\\arxsys.bmp")
SET(CPACK_NSIS_MUI_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\ressources\\\\dff.ico")
SET(CPACK_NSIS_MUI_UNIICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\ressources\\\\dff.ico")
SET(CPACK_NSIS_HELP_LINK "http://www.digital-forensic.org/")
SET(CPACK_NSIS_URL_INFO_ABOUT "http://www.arxsys.fr/")
SET(CPACK_NSIS_CONTACT "contact@arxsys.fr")
SET(CPACK_NSIS_MODIFY_PATH OFF)
SET(CPACK_NSIS_COMPRESSOR "/SOLID lzma")
SET(CPACK_GENERATOR "NSIS")


if(PROJECT_EDITION)
  string(TOLOWER ${PROJECT_EDITION} PROJECT_EDITION_LOWER)
  set(CPACK_SYSTEM_NAME "${PROJECT_EDITION_LOWER}-")
endif()
if(HAVE_64_BITS)
   set(CPACK_SYSTEM_NAME "${CPACK_SYSTEM_NAME}win64")
else()
   set(CPACK_SYSTEM_NAME "${CPACK_SYSTEM_NAME}win32")
endif()
if (WINALL)
   set(CPACK_SYSTEM_NAME "${CPACK_SYSTEM_NAME}_all_in_one")
endif()


if(PROJECT_EDITION)
  set(SHORTCUT_INFO "${PROJECT_EDITION} ")
else()
  set(SHORTCUT_INFO "")
endif()
set(SHORTCUT_INFO "${SHORTCUT_INFO}${TARGET_PLATFORM} bits")

set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS
  "
  SetOutPath \\\"$INSTDIR\\\\dff\\\"
  CreateShortCut \\\"$DESKTOP\\\\DFF ${SHORTCUT_INFO} (shell).lnk\\\" \\\"\\\$pypath\\\\python.exe\\\" \\\"\\\$\\\\\\\"$INSTDIR\\\\dff\\\\dff.py\\\$\\\\\\\"\\\" \\\"$INSTDIR\\\\dff\\\\ressources\\\\dff.ico\\\" 
  CreateShortCut \\\"$DESKTOP\\\\DFF ${SHORTCUT_INFO} (gui).lnk\\\" \\\"\\\$pypath\\\\pythonw.exe\\\" \\\"\\\$\\\\\\\"$INSTDIR\\\\dff\\\\dff-gui.pyw\\\$\\\\\\\"\\\" \\\"$INSTDIR\\\\dff\\\\ressources\\\\dff.ico\\\"  
  CreateShortCut \\\"$SMPROGRAMS\\\\DFF\\\\DFF ${SHORTCUT_INFO} (shell).lnk\\\" \\\"\\\$pypath\\\\python.exe\\\" \\\"\\\$\\\\\\\"$INSTDIR\\\\dff\\\\dff.py\\\$\\\\\\\"\\\" \\\"$INSTDIR\\\\dff\\\\ressources\\\\dff.ico\\\"  
  CreateShortCut \\\"$SMPROGRAMS\\\\DFF\\\\DFF ${SHORTCUT_INFO} bits (gui).lnk\\\" \\\"\\\$pypath\\\\pythonw.exe\\\" \\\"\\\$\\\\\\\"$INSTDIR\\\\dff\\\\dff-gui.pyw\\\$\\\\\\\"\\\" \\\"$INSTDIR\\\\dff\\\\ressources\\\\dff.ico\\\"  
  ")

#	# *.pyc files are not deleted by installer, because they are created at
#	# runtime. So, below, we force deletion of those files.

get_property(pyc_list GLOBAL PROPERTY PYC_FILES)
foreach (pyc_file ${pyc_list})
  set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS
      "${CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS}
      Delete \\\"$INSTDIR\\\\dff\\\\${pyc_file}\\\""
      )
endforeach (pyc_file ${pyc_list})


set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS
	"
	${CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS}
	Delete \\\"$DESKTOP\\\\DFF ${SHORTCUT_INFO} (shell).lnk\\\"
	Delete \\\"$DESKTOP\\\\DFF ${SHORTCUT_INFO} (gui).lnk\\\"
	Delete \\\"$SMPROGRAMS\\\\DFF\\\\DFF ${SHORTCUT_INFO} (shell).lnk\\\"
	Delete \\\"$SMPROGRAMS\\\\DFF\\\\DFF ${SHORTCUT_INFO} (gui).lnk\\\"
	")


  set(NSIS_HEADERS
	"
	!include \\\"LogicLib.nsh\\\"
        !include \\\"x64.nsh\\\"
	")

  if (HAVE_64_BITS)
     set(NSIS_HEADERS ${NSIS_HEADERS}
	"
	!define regview 64
	")
  else()
     set(NSIS_HEADERS ${NSIS_HEADERS}
	"
	!define regview 32
	")
  endif()

  set(NSIS_CHECK_PLATFORM_COMPAT
	"
	\\\${IfNot} \\\${RunningX64}
		\\\${If} ${TARGET_PLATFORM} == \\\"64\\\"
			MessageBox MB_OK|MB_ICONEXCLAMATION \\\"This version only works on 64 bits platform. Please install 32 bits version\\\"
			Abort
		\\\${EndIf}
	\\\${EndIf}
	")

  set(NSIS_PYTHON_PYQT_REGKEYS
	"
	Var /GLOBAL pypath
	Var /GLOBAL pyqtpath
	Var /GLOBAL py_hkcu_path
	Var /GLOBAL py_hklm_path

	StrCpy \\\$pypath \\\"\\\"
	StrCpy \\\$py_hkcu_path \\\"\\\"
	StrCpy \\\$py_hklm_path \\\"\\\"
	StrCpy \\\$pyqtpath \\\"\\\"
	\\\${If} \\\${RunningX64}
		SetRegView \\\${regview}
	\\\${EndIf}
	ReadRegStr \\\$py_hkcu_path HKCU \\\"SOFTWARE\\\\Python\\\\PythonCore\\\\2.7\\\\InstallPath\\\" \\\"\\\"
	ReadRegStr \\\$py_hklm_path HKLM \\\"SOFTWARE\\\\Python\\\\PythonCore\\\\2.7\\\\InstallPath\\\" \\\"\\\"
	ReadRegStr \\\$pyqtpath HKLM \\\"SOFTWARE\\\\PyQt4\\\\Py2.7\\\\InstallPath\\\" \\\"\\\"

	\\\${If} \\\$py_hklm_path != \\\"\\\"
		StrCpy \\\$pypath \\\$py_hklm_path
	\\\${Else}
		StrCpy \\\$pypath \\\$py_hkcu_path
	\\\${EndIf}
	"
	)

  set(NSIS_CHECK_PYTHON_PYQT_INSTALLED
	"
	\\\${If} \\\$pypath == \\\"\\\"
		MessageBox MB_OK|MB_ICONEXCLAMATION \\\"Python 2.7 ${TARGET_PLATFORM} bits not found.\\\$\\\\nPlease install it before installing DFF.\\\"
		Abort
	\\\${Else}
		Goto pyqt_check
	\\\${EndIf}
	pyqt_check:
		\\\${If} \\\$pyqtpath == \\\"\\\"
			MessageBox MB_OK|MB_ICONEXCLAMATION \\\"PyQt4 for Python 2.7 ${TARGET_PLATFORM} bits not found.\\\$\\\\nPlease install it before installing DFF.\\\"
			Abort
		\\\${Else}
			Goto inst
		\\\${EndIf}
	")

  set(NSIS_DFF_REGKEYS
	"
	Var /GLOBAL version32
	Var /GLOBAL version64
	Var /GLOBAL uninstall32
	Var /GLOBAL uninstall64
	Var /GLOBAL installed_version
	Var /GLOBAL uninstall_target

        StrCpy \\\$version32 \\\"\\\"
        StrCpy \\\$version64 \\\"\\\"
        StrCpy \\\$uninstall32 \\\"\\\"
        StrCpy \\\$uninstall64 \\\"\\\"
	StrCpy \\\$installed_version \\\"\\\"
	StrCpy \\\$uninstall_target \\\"\\\"
	
	\\\${If} \\\${RunningX64}
		SetRegView 64
		ReadRegStr \\\$version64 HKLM \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\dff\\\" \\\"DisplayVersion\\\"
		ReadRegStr \\\$uninstall64 HKLM \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\dff\\\" \\\"UninstallString\\\"
	\\\${EndIf}
	SetRegView 32
	ReadRegStr \\\$version32 HKLM \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\dff\\\" \\\"DisplayVersion\\\"
	ReadRegStr \\\$uninstall32 HKLM \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\dff\\\" \\\"UninstallString\\\"

	\\\${If} ${TARGET_PLATFORM} == \\\"64\\\"
		\\\${If} \\\$version64\\\ != \\\"\\\"
			StrCpy \\\$installed_version \\\$version64
			StrCpy \\\$uninstall_target \\\$uninstall64			
		\\\${EndIf}
	\\\${Else}
		\\\${If} \\\$version32 != \\\"\\\"
			StrCpy \\\$installed_version \\\$version32
			StrCpy \\\$uninstall_target \\\$uninstall32
		\\\${Endif}
	\\\${EndIf}
	")

  set(NSIS_DFF_INSTALL
	"
	inst:
		\\\${If} \\\$installed_version != \\\"\\\"
			MessageBox MB_YESNO|MB_ICONQUESTION \\\"DFF version \\\$installed_version is already installed.\\\$\\\\n\\\$\\\\nClick 'YES' to uninstall it first, or 'NO' to overwrite already installed version.\\\" IDYES uninst
			Goto done
		\\\${Else}
			Goto cont
		\\\${EndIf}

	end_with_errors:
		MessageBox MB_OK|MB_ICONEXCLAMATION \\\"Error uninstalling DFF version \\\$installed_version.\\\"
		Goto cont

	uninst:
		ClearErrors
		ExecWait '$uninstall_target _?=$INSTDIR'
		IfErrors end_with_errors
			MessageBox MB_OK|MB_ICONINFORMATION \\\"Uninstalling previous DFF version \\\$installed_version done, continue with install.\\\"
		Goto cont

	cont:
		File /r /x \\\"prerequisites\\\" \\\"\\\${INST_DIR}\\\\*.*\\\"
	
	done:
		
	"
	)
	
  # Common parts of CPACK_NSIS_FULL_INSTALL 
  set(CPACK_NSIS_FULL_INSTALL 
    ${CPACK_NSIS_FULL_INSTALL}
    ${NSIS_HEADERS}
    ${NSIS_CHECK_PLATFORM_COMPAT}
    )	
	
  if (WINALL)
    include("cmake_modules/dff/thirdparty_installers.cmake")
    message(STATUS "python installer: ${PYTHON_INSTALLER}")
    message(STATUS "pyqt installer: ${PYQT_INSTALLER}")
    message(STATUS "vcredist installer: ${VCREDIST_INSTALLER}")
    message(STATUS "apsw installer: ${APSW_INSTALLER}")
    message(STATUS "numpy installer: ${NUMPY_INSTALLER}")
    message(STATUS "matplotlib installer: ${MATPLOTLIB_INSTALLER}")
    message(STATUS "PIL installer: ${PIL_INSTALLER}")
    message(STATUS "Volatility installer: ${VOLATILITY_INSTALLER}")
    
    set(CPACK_NSIS_FULL_INSTALL
	${CPACK_NSIS_FULL_INSTALL}
	${NSIS_DFF_REGKEYS}
	"
	MessageBox MB_YESNO \\\"Install ${PYTHON_INSTALLER} ? \\\" /SD IDYES IDNO InstPyQt
	File \\\"/oname=$TEMP\\\\${PYTHON_INSTALLER}\\\" \\\"\\\${INST_DIR}\\\\dff\\\\prerequisites\\\\${PYTHON_INSTALLER}\\\"
	ExecWait '\\\"msiexec\\\" /i \\\"$TEMP\\\\${PYTHON_INSTALLER}\\\"'
	Delete \\\"$TEMP\\\\${PYTHON_INSTALLER}\\\"
	Goto InstPyQt
	InstPyQt:
		MessageBox MB_YESNO \\\"Install ${PYQT_INSTALLER} ? \\\" /SD IDYES IDNO InstAPSW
		File \\\"/oname=$TEMP\\\\${PYQT_INSTALLER}\\\" \\\"\\\${INST_DIR}\\\\dff\\\\prerequisites\\\\${PYQT_INSTALLER}\\\"
		ExecWait '\\\"$TEMP\\\\${PYQT_INSTALLER}\\\"'
		Delete \\\"$TEMP\\\\${PYQT_INSTALLER}\\\"
		Goto InstAPSW
	InstAPSW:
		MessageBox MB_YESNO \\\"Install ${APSW_INSTALLER}? \\\" /SD IDYES IDNO InstPil
		File \\\"/oname=$TEMP\\\\${APSW_INSTALLER}\\\" \\\"\\\${INST_DIR}\\\\dff\\\\prerequisites\\\\${APSW_INSTALLER}\\\"
		ExecWait '\\\"$TEMP\\\\${APSW_INSTALLER}\\\"'
		Delete \\\"$TEMP\\\\${APSW_INSTALLER}\\\"
		Goto InstPil
	InstPil:
		MessageBox MB_YESNO \\\"Install ${PIL_INSTALLER}? \\\" /SD IDYES IDNO InstVolatility
		File \\\"/oname=$TEMP\\\\${PIL_INSTALLER}\\\" \\\"\\\${INST_DIR}\\\\dff\\\\prerequisites\\\\${PIL_INSTALLER}\\\"
		ExecWait '\\\"$TEMP\\\\${PIL_INSTALLER}\\\"'
		Delete \\\"$TEMP\\\\${PIL_INSTALLER}\\\"
		Goto InstVolatility
	InstVolatility:
		MessageBox MB_YESNO \\\"Install ${VOLATILITY_INSTALLER}? \\\" /SD IDYES IDNO InstVcredist
		File \\\"/oname=$TEMP\\\\${VOLATILITY_INSTALLER}\\\" \\\"\\\${INST_DIR}\\\\dff\\\\prerequisites\\\\${VOLATILITY_INSTALLER}\\\"
		ExecWait '\\\"$TEMP\\\\${VOLATILITY_INSTALLER}\\\"'
		Delete \\\"$TEMP\\\\${VOLATILITY_INSTALLER}\\\"
		Goto InstVcredist
	")
    if (BUILD_UNSUPPORTED)
      set(CPACK_NSIS_FULL_INSTALL ${CPACK_NSIS_FULL_INSTALL}
	"
	InstVcredist:
		MessageBox MB_YESNO \\\"Install Microsoft Visual Studio DLL dependencies ? \\\" /SD IDYES IDNO InstNumpy
		File \\\"/oname=$TEMP\\\\${VCREDIST_INSTALLER}\\\" \\\"\\\${INST_DIR}\\\\dff\\\\prerequisites\\\\${VCREDIST_INSTALLER}\\\"
		ExecWait '\\\"$TEMP\\\\${VCREDIST_INSTALLER}\\\" /q:a'
		Delete \\\"$TEMP\\\\${VCREDIST_INSTALLER}\\\"
		Goto InstNumpy
	InstNumpy:
		MessageBox MB_YESNO \\\"Install ${NUMPY_INSTALLER}? \\\" /SD IDYES IDNO InstMatplotlib
		File \\\"/oname=$TEMP\\\\${NUMPY_INSTALLER}\\\" \\\"\\\${INST_DIR}\\\\dff\\\\prerequisites\\\\${NUMPY_INSTALLER}\\\"
		ExecWait '\\\"$TEMP\\\\${NUMPY_INSTALLER}\\\"'
		Delete \\\"$TEMP\\\\${NUMPY_INSTALLER}\\\"
		Goto InstMatplotlib
	IntMatplotlib:
		MessageBox MB_YESNO \\\"Install ${MATPLOTLIB_INSTALLER}? \\\" /SD IDYES IDNO
		File \\\"/oname=$TEMP\\\\${MATPLOTLIB_INSTALLER}\\\" \\\"\\\${INST_DIR}\\\\dff\\\\prerequisites\\\\${MATPLOTLIB_INSTALLER}\\\"
		ExecWait '\\\"$TEMP\\\\${MATPLOTLIB_INSTALLER}\\\"'
		Delete \\\"$TEMP\\\\${MATPLOTLIB_INSTALLER}\\\"
	")
    else()
      set(CPACK_NSIS_FULL_INSTALL ${CPACK_NSIS_FULL_INSTALL}
	"
	InstVcredist:
		MessageBox MB_YESNO \\\"Install Microsoft Visual Studio 2010 DLL dependencies ? \\\" /SD IDYES IDNO InstVcredist13
		File \\\"/oname=$TEMP\\\\${VCREDIST10_INSTALLER}\\\" \\\"\\\${INST_DIR}\\\\dff\\\\prerequisites\\\\${VCREDIST10_INSTALLER}\\\"
		ExecWait '\\\"$TEMP\\\\${VCREDIST10_INSTALLER}\\\" /q:a'
		Delete \\\"$TEMP\\\\${VCREDIST10_INSTALLER}\\\"
		Goto InstVcredist13
	InstVcredist13:
		MessageBox MB_YESNO \\\"Install Microsoft Visual Studio 2013 DLL dependencies ? \\\" /SD IDYES IDNO
		File \\\"/oname=$TEMP\\\\${VCREDIST13_INSTALLER}\\\" \\\"\\\${INST_DIR}\\\\dff\\\\prerequisites\\\\${VCREDIST13_INSTALLER}\\\"
		ExecWait '\\\"$TEMP\\\\${VCREDIST13_INSTALLER}\\\" /q:a'
		Delete \\\"$TEMP\\\\${VCREDIST13_INSTALLER}\\\"
        ")
    endif()

    set(CPACK_NSIS_FULL_INSTALL ${CPACK_NSIS_FULL_INSTALL}
	${NSIS_PYTHON_PYQT_REGKEYS}
	"
	Goto inst
	"
	${NSIS_DFF_INSTALL}
	)

  else(WINALL)
    set(CPACK_NSIS_FULL_INSTALL ${CPACK_NSIS_FULL_INSTALL}
	${NSIS_PYTHON_PYQT_REGKEYS}
	${NSIS_DFF_REGKEYS}
	${NSIS_CHECK_PYTHON_PYQT_INSTALLED}
	${NSIS_DFF_INSTALL}
      )
  endif(WINALL)
  SET(CPACK_SOURCE_GENERATOR "ZIP")
  
  SET(CMAKE_INSTALL_PREFIX "")
