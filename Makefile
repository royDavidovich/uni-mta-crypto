# Compiler and flags
CC       := gcc
CFLAGS   := -std=c11 -Iinclude -pthread -Wall -Wextra -g

# Directories
SRCDIR   := src
INCDIR   := include
OBJDIR   := obj

# Target executable
TARGET   := mta_crypto

# Source files and their corresponding objects in obj/
SRCS     := $(wildcard $(SRCDIR)/*.c)
OBJS     := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

# Libraries
LIBS     := -lmta_crypt -lmta_rand -lcrypto

.PHONY: all clean

all: $(TARGET)
	@echo "$(TARGET) is up to date!"

# Link step
$(TARGET): $(OBJS)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
	@echo "Build complete!"

# Compile step: place .o files into obj/
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	@echo "Compiling $< → $@"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJDIR) $(TARGET)
	@echo "Cleaned up build artifacts."