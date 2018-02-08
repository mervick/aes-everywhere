MCS = mcs
MONO = mono

CSFLAGS =
FLAGS =

DIR = src
TARGET = aes256

all: $(TARGET)

$(TARGET): $(DIR)/$(TARGET).cs
	$(RM) $(DIR)/*.exe
	$(MCS) $(CSFLAGS) $(DIR)/*.cs
	$(MONO) $(FLAGS) $(DIR)/$(TARGET).exe

clean:
	$(RM) $(DIR)/*.exe
