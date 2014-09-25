LOCAL_INCLUDES = -Italos
FRAMEWORKS = -framework Cocoa -framework Security
FLAGS = -Wall -Wno-deprecated
OUTPUT_NAME = 1Password2KeyChain

all:
	g++ 	-o $(OUTPUT_NAME)		\
		$(FLAGS)			\
		$(FRAMEWORKS)                   \
		$(LOCAL_INCLUDES)		\
		main.m	 			\
		talos/AgileCrypto.m		\
		talos/AgileKey.m		\
		talos/AgileKeychain.m		\
		talos/AgileKeychainItem.m	\
		talos/NSData+Base64Decode.m

clean:
	rm -f $(OUTPUT_NAME) $(OUTPUT_NAME).dSYM
