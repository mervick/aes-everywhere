TARGET := a.out

SRC_DIR := src
OBJ_DIR := build
SRC_FILES := $(wildcard $(SRC_DIR)/*.cpp)
OBJ_FILES := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC_FILES))
LDFLAGS :=
CPPFLAGS :=
CXXFLAGS :=
MKDIR_P ?= mkdir -p


build: clean mkdir $(OBJ_DIR)/$(TARGET)

mkdir:
	$(MKDIR_P) $(OBJ_DIR)

$(OBJ_DIR)/$(TARGET): $(OBJ_FILES)
	$(MKDIR_P) $(dir $@)
	$(CXX) $(LDFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

clean:
	$(RM) -r $(OBJ_DIR) $(OBJ_DIR)/*.o
