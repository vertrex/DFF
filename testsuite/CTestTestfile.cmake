# CMake generated Testfile for 
# Source directory: /home/vertrex/dff-pro/testsuite
# Build directory: /home/vertrex/dff-pro/testsuite
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(modules.fs.local "python" "local.py")
add_test(modules.parser.hash "python" "hashtest.py")
add_test(modules.fs.fat "python" "fattest.py")
add_test(modules.api.env.error "python" "enverrortest.py")
add_test(modules.api.vfs.error "python" "vfserrortest.py")
