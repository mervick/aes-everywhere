#CXX = g++
#CFLAGS = $(OPENSSL_INCS_LOCATION) -g -Wall -Wextra
CFLAGS = $(OPENSSL_INCS_LOCATION) -std=gnu++11 -g -Wall -Wno-comment -Wno-parentheses -Wno-unused-variable -Wno-maybe-uninitialized
LDFLAGS = $(OPENSSL_LIBS_LOCATION) -lssl -lcrypto

DIR = src
TARGET = aes256

all: $(TARGET)

$(TARGET): $(DIR)/$(TARGET).cpp
	$(CXX) $(CFLAGS) -o $(TARGET) $< $(LDFLAGS)

clean:
	$(RM) $(TARGET) $(DIR)/*.o $(PATH)/*~
